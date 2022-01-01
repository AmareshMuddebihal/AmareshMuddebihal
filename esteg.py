#!/usr/bin/env python3

#   Copyright (C) 2021 Jithin Renji
#
#   ESteg is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   ESteg is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>

import argparse
import traceback

from sys import stderr
from PIL import Image
from colorama import Fore, Back, Style


def get_nth_bit(val: int, n: int) -> int:
    """
    Get the nth bit from the left.
    """
    return (val & (0b10000000 >> (n - 1))) >> (7 - (n - 1))


def set_nth_bit(val: int, n: int) -> int:
    val |= 0b10000000 >> (n - 1)
    return val

def unset_nth_bit(val: int, n: int) -> int:
    val &= ~(0b10000000 >> (n - 1))
    return val


def set_nth_bit_to_bit(val: int, bit: int, n: int) -> int:
    """
    Set the nth bit from the left to bit.
    """
    if get_nth_bit(val, n) == 1:
        if bit == 0:
            val = unset_nth_bit(val, n)

    elif get_nth_bit(val, n) == 0:
        if bit == 1:
            val = set_nth_bit(val, n)

    return val


def embed(msg_fname: str, img_fname: str) -> None:
    try:
        img = Image.open(img_fname)
        pixels = img.getdata()
        pix_data = []

        if img.format != 'PNG':
            raise Exception("Only PNG images are supported.")

        # Convert list of triplets to list of values
        for pixel in pixels:
            for val in pixel:
                pix_data.append(val)

        with open(msg_fname) as fhandle:
            print(
                Fore.GREEN + Style.BRIGHT +
                f"Embedding" +
                Fore.WHITE + Style.BRIGHT +
                f" '{msg_fname}'" +
                Fore.GREEN + Style.BRIGHT +
                f" in " +
                Fore.WHITE + Style.BRIGHT +
                f"'{img_fname}' " +
                Fore.GREEN + Style.BRIGHT +
                f"..." +
                Style.RESET_ALL,
                file=stderr
            )

            msg = bytes(fhandle.read(), encoding='ascii')
            msg_len = len(msg).to_bytes(4, byteorder='big')
            msg = msg_len + msg

            # Each component of a pixel will store 2 bits of each byte in the
            # message. So, len(msg) * 4 should be <= len(data)
            if len(msg) * 4 > len(pix_data):
                raise Exception("Message is too long.")

            duplets = []

            # Split each byte of the messege into duplets
            for byte in msg:
                for i in range(7, -1, -2):
                    duplets.append((byte & (0b11000000 >> (7 - i))) >> (i - 1))

            # Change the 7th and 8th bits of each value to the 7th and 8th
            # bit of each duplet.
            for val, i in zip(pix_data, range(len(duplets))):
                pix_data[i] = set_nth_bit_to_bit(pix_data[i], get_nth_bit(duplets[i], 7), 7)
                pix_data[i] = set_nth_bit_to_bit(pix_data[i], get_nth_bit(duplets[i], 8), 8)

            steg_img = Image.frombytes('RGB', (img.width, img.height), bytes(pix_data))
            steg_img.save(img_fname + "_esteg.png")
            print(
                Fore.GREEN + Style.BRIGHT +
                f"Done! Steganographic image saved to " +
                Fore.WHITE + Style.BRIGHT +
                f"'{img_fname + '_esteg.png'}' " +
                Fore.GREEN + Style.BRIGHT +
                f".",
                file=stderr
            )

    except Exception as e:
        # print(traceback.format_exc())
        print(
            Fore.RED + Style.BRIGHT +
            "Error: " + Fore.RESET + str(e) +
            Style.RESET_ALL, file=stderr
        )


def extract(img_fname: str) -> str:
    try:
        img = Image.open(img_fname)
        if img.format != 'PNG':
            raise Exception("Only PNG images are supported.")

        print(
            Fore.GREEN + Style.BRIGHT +
            f"Extracting message from " +
            Fore.WHITE + Style.BRIGHT +
            f"'{img_fname}' " +
            Fore.GREEN + Style.BRIGHT +
            f"..." +
            Style.RESET_ALL, file=stderr
        )

        pixels = img.getdata()
        pix_data = []

        # Convert list of triplets to list of values
        for pixel in pixels:
            for val in pixel:
                pix_data.append(val)

        # First 16 bytes contain the length of the message.
        size = b""
        duplets = []
        for i in range(16):
            duplet = 0
            duplet = set_nth_bit_to_bit(duplet, get_nth_bit(pix_data[i], 7), 7)
            duplet = set_nth_bit_to_bit(duplet, get_nth_bit(pix_data[i], 8), 8)
            duplets.append(duplet)

            if len(duplets) == 4:
                byte = 0
                for dup, j in zip(duplets, range(6, -1, -2)):
                    byte |= (dup << j)

                size += byte.to_bytes(1, byteorder='big')
                duplets.clear()

        size = int.from_bytes(size, byteorder='big')
        print(
            Fore.GREEN + Style.BRIGHT +
            f"Probable message length: " +
            Fore.WHITE + Style.BRIGHT +
            f"{size}" +
            Style.RESET_ALL, file=stderr
        )

        print(
            Fore.GREEN + Style.BRIGHT +
            f"Probable message:" +
            Style.RESET_ALL, file=stderr
        )

        # First 16 bytes of the image contain the size, which is not part of the
        # original message, so we get rid of it.
        pix_data = pix_data[16:]
        for i in range(size * 4):
            duplet = 0
            duplet = set_nth_bit_to_bit(duplet, get_nth_bit(pix_data[i], 7), 7)
            duplet = set_nth_bit_to_bit(duplet, get_nth_bit(pix_data[i], 8), 8)
            duplets.append(duplet)

            if len(duplets) == 4:
                byte = 0
                for dup, j in zip(duplets, range(6, -1, -2)):
                    byte |= (dup << j)

                print(
                    byte.to_bytes(1, byteorder='big').decode('ASCII'),
                    file=stderr, end=""
                )
                duplets.clear()

    except Exception as e:
        # print(traceback.format_exc())
        print(
            Fore.RED + Style.BRIGHT +
            "Error: " + Fore.RESET + str(e) +
            Style.RESET_ALL, file=stderr
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple steganography program")
    parser.add_argument('img_fname', metavar='IMG_FNAME', type=str,
                        help="name of the image file")
    parser.add_argument('--version', action='version', version='ESteg v0.1',
                        help="show version infomation and exit")
    parser.add_argument('--embed', type=str, metavar="FNAME",
                        help="embed FNAME in IMG_FNAME [default behavior is to extract]")

    args = parser.parse_args()
    if args.embed is not None:
        embed(args.embed, args.img_fname)

    else:
        extract(args.img_fname)


if __name__ == '__main__':
    main()
