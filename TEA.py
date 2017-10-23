"""
# Author: Joshua Church
# Assignment 3: Analyze the confusion and diffusion properties of TEA cipher
# K7 
"""
import random
from random import getrandbits
import hashlib
from operator import xor
import copy
import math

# Creates random 64-bit plaintext message
def generate_message():
	return [getrandbits(32), getrandbits(32)]


# Creates random 128-bit key
def generate_key():
	return [getrandbits(32), getrandbits(32), getrandbits(32), getrandbits(32)]

# Flip bits in message to show diffusion property of TEA. 
def diffusion_flip_bits_in_message(v):
	random_bit = random.randint(0, 63)
	bit_to_flip = random_bit % 32

	if random_bit <= 31:
		message_block = 0
	else:
		message_block = 1

	binary = "{:032b}".format(v[message_block])	
	flipped_key_block = (binary[:bit_to_flip] if bit_to_flip != 0 else '') + ('0' if binary[bit_to_flip] is '1' else '1') + ('' if bit_to_flip == 31 else binary[(bit_to_flip+1):])

	if random_bit <= 32:
		v0 = int(flipped_key_block, 2)
		return [v0, v[1]]
	else:
		v1 = int(flipped_key_block, 2)
		return [v[0], v1]

# Flip bits in key to show confusion property of TEA. 
def confusion_flip_bits_in_key(k, k7):
	bit_to_flip = k7 % 32
	binary = "{:032b}".format(k[1])
	flipped_key_block = binary[:bit_to_flip] + ('0' if binary[bit_to_flip] is '1' else '1') + ('' if bit_to_flip == 31 else binary[(bit_to_flip+1):])
	k1 = int(flipped_key_block, 2)
	return [k[0], k1, k[2], k[3]]


def XOR(c, c_prime, summation, hist):

	block_size = 64
	block1 = c[0] ^ c_prime[0]
	block2 = c[1] ^ c_prime[1]

	number_of_zeroes_block1 = bin(block1).count('0')
	number_of_ones_block1 = bin(block1).count('1')

	number_of_zeroes_block2 = bin(block2).count('0')
	number_of_ones_block2 = bin(block2).count('1')

	hist[3].append(number_of_ones_block1 + number_of_ones_block2)
	z0 = float(number_of_ones_block1) / (number_of_zeroes_block1 + number_of_ones_block1) 
	z1 = float(number_of_ones_block2) / (number_of_zeroes_block2 + number_of_ones_block2)
	z = (z0 + z1) / 2
	z = z * block_size
	summation.append(z)

def average(summation):
	mean = float(sum(summation)/len(summation))
	return mean

def variance(mean, summation):
	var = []

	for z in summation:
		z = (z-mean)**2
		var.append(z) 

	var = float(sum(var)) / len(summation)
	var = mean / var
	return var

def standard_deviation(var):
	stand_dev = math.sqrt(var)
	return stand_dev

def histogram_key(hist):
	print("\nHISTOGRAM\n")

	bit = 56

	print("Each '*' represents 3 ones found in the XOR'd ciphertext.")
	print("The following represents the average number of counted ones. (after 1000 iterations of each flipped bit)\n")

	for i in range(8):
		print(" --> Round " + str(i+1) + ": " + '*'*(hist[3][i] / 3))

	print("\nByte given to flip in the key: k7 (bits 56 - 63))")
	for i in range(8):
		print("\nFlipping bit " + str(bit) + " in the key.")
		for j in range(3):
			if j == 0:
				print(" --> Mean: " + str(hist[j][i]))
			if j == 1:
				print(" --> Variance: " + str(hist[j][i]))
			if j == 2:
				print(" --> Standard Deviation: " + str(hist[j][i]))

		bit += 1

def histogram_message(hist):
	print("\nHISTOGRAM\n")

	bit = 56

	print("Each '*' represents 3 ones found in the XOR'd ciphertext.")
	print("The following represents the average number of counted ones. (after 1000 iterations of each flipped bit)\n")

	for i in range(8):
		print(" --> Round " + str(i+1) + ": " + '*'*(hist[3][i] / 3))

	for i in range(8):
		print("\nFlipping random bit in the message")
		for j in range(3):
			if j == 0:
				print(" --> Mean: " + str(hist[j][i]))
			if j == 1:
				print(" --> Variance: " + str(hist[j][i]))
			if j == 2:
				print(" --> Standard Deviation: " + str(hist[j][i]))

		bit += 1

def encode(v, k):

	# Set up
	y = v[0]
	z = v[1] 
	summation = 0
	
	# A key schedule constant
	delta = 0x9e3779b9
	n = 32

	while (n > 0):
		n = n - 1
		summation += delta
		y += (z << 4) + k[0] ^ z + summation ^ (z >> 5) + k[1]
		z += (y << 4) + k[2] ^ y + summation ^ (y >> 5) + k[3]

	v[0] = y
	v[1] = z 

	return v

def decode(v, k):
	
	y = v[0]
	z = v[1] 
	summation = 0
	delta = 0x9e3779b9
	n = 32

	summation = delta << 5

	while (n > 0):
		n = n - 1
		z -= (y << 4) + k[2] ^ y + summation ^ (y >> 5) + k[3]
		y -= (z << 4) + k[0] ^ z + summation ^ (z >> 5) + k[1]
		summation -= delta

	v[0] = y
	v[1] = z 

	return v

if __name__ == "__main__":
	count = 8000
	k7 = 56
	summation = []
	hist = [[], [], [], []]

	# Confusion means that each binary digit (bit) of the ciphertext should depend on several parts of the key.
	print(" ===== CONFUSION PROPERTY OF TEA ===== ")
	while (count > 0):
		
		# Change to bit 57
		if (count == 7000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		# Change to bit 58
		elif (count == 6000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		# Change to bit 59
		elif (count == 5000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		# Change to bit 60
		elif (count == 4000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		# Change to bit 61
		elif (count == 3000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			hist[3].append(summation)
			summation = []

		# Change to bit 62
		elif (count == 2000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		# change to bit 63
		elif (count == 1000):
			k7 += 1
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count-1 == 0):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)

		v = generate_message()
		v_prime = copy.deepcopy(v)
		k = generate_key()
		k_prime = confusion_flip_bits_in_key(k, k7)

		# Get the cyphertext
		c = encode(v, k)
		c_prime = encode(v_prime, k_prime)
	
		XOR(c, c_prime, summation, hist)
		count -= 1

	histogram_key(hist)

	# Diffusion means that if we change a single bit of the plaintext, then (statistically) 
	# half of the bits in the ciphertext should change, and similarly, if we change one
	# bit of the ciphertext, then approximately one half of the plaintext bits should change

	count = 8000
	summation = []
	hist = [[], [], [], []]
	print(" \n\n===== DIFFUSION PROPERTY OF TEA ===== ")
	while (count > 0):
		
		if (count == 7000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count == 6000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count == 5000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count == 4000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count == 3000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			hist[3].append(summation)
			summation = []

		elif (count == 2000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count == 1000):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)
			summation = []

		elif (count-1 == 0):
			mean = average(summation)
			var = variance(mean, summation)
			stand_dev = standard_deviation(var)
			hist[0].append(mean)
			hist[1].append(var)
			hist[2].append(stand_dev)

		v = generate_message()
		v_prime = diffusion_flip_bits_in_message(copy.deepcopy(v))
		k = generate_key()
		k_prime = copy.deepcopy(k)

		# Get the cyphertext
		c = encode(v, k)
		c_prime = encode(v_prime, k_prime)
	
		XOR(c, c_prime, summation, hist)
		count -= 1

	histogram_message(hist)



	

