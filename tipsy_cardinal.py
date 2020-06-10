#!/usr/bin/python3.5
###################################################################################################
__author__ = "John Vennard"
__credits__ = "https://pthree.org/2013/05/30/openssh-keys-and-the-drunken-bishop/"
__version__ = "1.0"
__status__ = "Development"
###################################################################################################

""" Purpose: Takes md5 fingerprint of SSH key and outputs SSH art based on the drunken bishop algorithm. """

import os
import time
import argparse
import binascii

class Board():

    DISP_LIST = [' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^', 'S', 'E']
    POS_START = (8, 4)

    def __init__(self):
        self.pos = self.POS_START
        self.width = 17
        self.height = 9
        self.map = [[0 for y in range(self.height)] for x in range(self.width)]
        self.set_loc(self.pos)
        self.move_keys = []
        self.index = 0
        self.last_pos = (0, 0)

    def final(self):
        sx, sy = self.POS_START
        ex, ey = self.last_pos
        self.map[sx][sy] = len(self.DISP_LIST) - 2
        self.map[ex][ey] = len(self.DISP_LIST) - 1

    def step(self):
        if self.index >= len(self.move_keys):
            self.last_pos = self.pos
            return False
        else:
            move = self.move_keys[self.index]
            self.index += 1
            self.update(move)
            return True

    def set_loc(self, pos):
        x_set, y_set = pos
        self.pos = pos
        for x in range(self.width):
            for y in range(self.height):
                if x_set == x and y_set == y:
                    self.map[x][y] += 1

    def update(self, direction):
        ''' Direction codes: 
            00 - NW
            01 - NE
            10 - SW
            11 - SE
        '''
        new_pos = (0, 0) 
        x, y = self.pos
        ok_move = False
        if self.pos == (0, 0):  # NW Corner
            if direction == '00':
                new_pos = (x, y)
            elif direction == '01':
                new_pos = (x + 1, y)
            elif direction == '10':
                new_pos = (x, y + 1)
            else:
                ok_move = True
        elif self.pos == (self.width - 1, 0):  # NE Corner
            if direction == '00':
                new_pos = (x - 1, y)
            elif direction == '01':  
                new_pos = (x, y)
            elif direction == '11':
                new_pos = (x, y + 1)
            else:
                ok_move = True
        elif self.pos == (0, self.height - 1):  # SW Corner
            if direction == '00':
                new_pos = (x, y - 1)
            elif direction == '10':
                new_pos = (x, y)
            elif direction == '11':
                new_pos = (x + 1, y)
            else:
                ok_move = True
        elif self.pos == (self.width - 1, self.height - 1):  # SE Corner
            if direction == '01':
                new_pos = (x, y - 1)
            elif direction == '10':
                new_pos = (x - 1, y)
            elif direction == '11':
                new_pos = (x, y)
            else:
                ok_move = True
        elif self.pos[0] >= 0 and self.pos[0] < self.width and self.pos[1] == 0:  # Top Edge
            if direction == '00':
                new_pos = (x - 1, y)
            elif direction == '01':
                new_pos = (x + 1, y)
            else:
                ok_move = True
        elif self.pos[0] >= 0 and self.pos[0] < self.width and self.pos[1] == (self.height - 1):  # Bottom Edge
            if direction == '10':
                new_pos = (x - 1, y)
            elif direction == '11':
                new_pos = (x + 1, y)
            else:
                ok_move = True
        elif self.pos[0] == (self.width - 1) and self.pos[1] >= 0 and self.pos[1] < self.height:  # Right Edge
            if direction == '01':
                new_pos = (x, y - 1)
            elif direction == '11':
                new_pos = (x, y + 1)
            else:
                ok_move = True
        elif self.pos[0] == 0 and self.pos[1] >= 0 and self.pos[1] < self.height:  # Left Edge
            if direction == '00':
                new_pos = (x, y - 1)
            elif direction == '10':
                new_pos = (x, y + 1)
            else:
                ok_move = True
        elif 0 < self.pos[0] < self.width - 1 and 0 < self.pos[1] < self.height - 1:  # Center Board
            ok_move = True
        else:
            print("Error: logical mistep")
            exit(0)
        
        if ok_move:
            if direction == '00':  # NW
                new_pos = (x - 1, y - 1)
            if direction == '01':  # NE
                new_pos = (x + 1, y - 1)
            if direction == '10':  # SW
                new_pos = (x - 1, y + 1)
            if direction == '11':  # SE
                new_pos = (x + 1, y + 1)
        #print("Updating location from ({}) ---> ({})".format(self.pos, new_pos))    
        self.set_loc(new_pos)

    def draw(self):
        print("+-----------------+")
        for y in range(self.height):
            row = "|"
            for x in range(self.width):
                ind = self.map[x][y]
                if ind >= len(self.DISP_LIST):
                    print("index out of bounds: {}".format(ind))
                else:
                    row += str(self.DISP_LIST[ind])
            row += "|" + str(y)
            print(row)
        print("+-----------------+")

    def import_key(self, key):
        ''' Converts ssh hash into 2 bit chunks - bit pairs are read little endian (right-to-left) '''
        for i in range(int(len(key)/2)):
            hex_pair = key[(i*2)] + key[(i*2)+1]
            byte_pair = binascii.unhexlify(hex_pair)
            int_pair = int.from_bytes(byte_pair, byteorder='big')
            str_pair = format(int_pair, '#010b')[2:]
            to_little_endian = []
            for k in range(4):
                to_little_endian.append(str_pair[(k*2)] + str_pair[(k*2)+1])
            for out in reversed(to_little_endian):
                self.move_keys.append(out)
        print("Finished converting key.")

def get_inputs():
    ''' Get parameter input and validate '''
    parser = argparse.ArgumentParser()
    parser.add_argument("md5sum", type=str, help="Md5 hash of ssh key")
    args = parser.parse_args()
    print("- input: {}".format(args.md5sum))
    return args.md5sum

if __name__ == "__main__":
    print("Launching...")
    key = get_inputs()
    my_board = Board()
    my_board.import_key(key)
    while my_board.step():
        os.system('cls' if os.name == 'nt' else 'clear')
        my_board.draw()
        time.sleep(0.1)
    os.system('cls' if os.name == 'nt' else 'clear')
    my_board.final()
    my_board.draw()
    print("completed.")
    exit(0)


