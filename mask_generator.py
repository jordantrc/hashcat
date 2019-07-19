# mask_generator.py
#
# Generates a list of hashcat masks that are compliant
# with Microsoft AD password complexity requirements
#
# Usage: mask_generator.py <length>
#   length can be a single number or a range, e.g. 8-10
#

import itertools
import math
import sys

class PasswordMask():

    def __init__(self, mask):
        self.mask = mask
        self.entropy = self.calculate_entropy()
        self.compliant = self.assess_mask()
        self.user_friendliness = self.calculate_user_friendliness()
        
        # convert to hashcat format
        self.mask_string = '?'
        self.mask_string += '?'.join(mask)

        # risk score is the entropy divided by user friendliness
        # example1: entropy = 30 bits, user friendliness = 100 = 0.3
        # example2: entropy = 28 bits, user friendliness = 100 = 0.28 - this password is more risky
        if self.user_friendliness != 0:
            self.risk_score = float(self.entropy) / self.user_friendliness
        else:
            self.risk_score = float(self.entropy) / .001

    def assess_mask(self):
        '''ensures the mask is compliant, it must have three of the four character types'''
        result = None
        counts = [self.mask.count('l'), self.mask.count('u'), self.mask.count('d'), self.mask.count('s')]

        # three of the above have to be non-zero
        num_non_zero = len(counts) - counts.count(0)
        if num_non_zero >= 3:
            result = True
        else:
            result = False

        return result


    def calculate_entropy(self):
        '''calculates the bits of entropy for the given mask'''
        counts = [self.mask.count('l'), self.mask.count('u'), self.mask.count('d'), self.mask.count('s')]

        count_letter_places = counts[0] + counts[1]
        count_digit_places = counts[2]
        count_special_places = counts[3]

        combinations = 1
        if count_letter_places > 0:
            combinations *= math.pow(26, count_letter_places)
        if count_digit_places > 0:
            combinations *= math.pow(10, count_digit_places)
        if count_special_places > 0:
            combinations *= math.pow(30, count_special_places)

        entropy = int(math.log(combinations, 2))
        return entropy

    def calculate_user_friendliness(self):
        '''calculates a "user friendliness" score, which is based on the assumption
        that the user will prefer passwords with the same character type in sequential
        characters, and will prefer to not use special characters or upper case characters
        since they generally require a second key press (SHIFT), higher scores are better'''
        score = 100

        for i, c in enumerate(self.mask):
            # subtract 10 points if SHIFT was used, add two points if lower
            # case character
            if c == 'u' or c == 's':
                score -= 10
            if c == 'l':
                score += 2

            # add points if this character type is the same as the last character type
            if i != 0:
                if c == self.mask[i - 1]:
                    score += 5

        return score


def main():
    '''main function'''
    length_arg = sys.argv[1]
    lengths = []
    if '-' in length_arg:
        start, end = length_arg.split('-')
        start = int(start)
        end = int(end)
        assert start < end
    else:
        start = int(length_arg)
        end = start + 1
    lengths = list(range(start, end))

    # generates masks
    type_strings = 'ulds'
    compliant_masks = []

    for l in lengths:
        combinations = itertools.product(type_strings, repeat=l)

        count_total = 0
        count_valid = 0
        for c in combinations:
            mask = PasswordMask(c)
            count_total += 1
            if mask.compliant:
                compliant_masks.append(mask)
                count_valid += 1

        print("generated %s valid masks from %s possible combinations:" % (count_valid, count_total))

    # print final list, sorted by risk score
    compliant_masks.sort(key=lambda x: x.risk_score)
    for m in compliant_masks:
        print("%s" % (m.mask_string))


if __name__ == '__main__':
    main()
