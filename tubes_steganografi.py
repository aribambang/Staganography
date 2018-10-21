#!/usr/bin/python3

from cv2 import imread,imwrite
import logging
import numpy as np
from base64 import urlsafe_b64encode
from hashlib import md5
from cryptography.fernet import Fernet
from custom_exceptions import *


#representasi string biner 
def str2bin(string):
    return ''.join((bin(ord(i))[2:]).zfill(7) for i in string)

#representasi teks dari string biner
def bin2str(string):
    return ''.join(chr(int(string[i:i+7],2)) for i in range(len(string))[::7])

#Mengembalikan bentuk string terenkripsi / didekripsi tergantung pada input mode
def encrypt_decrypt(string,password,mode='enc'):
    _hash = md5(password.encode()).hexdigest()
    cipher_key = urlsafe_b64encode(_hash.encode())
    cipher = Fernet(cipher_key)
    if mode == 'enc':
        return cipher.encrypt(string.encode()).decode()
    else:
        return cipher.decrypt(string.encode()).decode()


#Enkripsi data dalam gambar
def encode(input_filepath,text,output_filepath,password,progressBar=None):
    data = encrypt_decrypt(text,password,'enc') #mengkripsi teks dan password
    data_length = bin(len(data))[2:].zfill(32)
    bin_data = iter(data_length + str2bin(data))
    img = imread(input_filepath,1)
    if img is None:
        raise FileError("Gambar '{}' tidak ditemukan".format(input_filepath))
    height,width = img.shape[0],img.shape[1]
    encoding_capacity = height*width*3
    total_bits = 32+len(data)*7
    if total_bits > encoding_capacity:
        raise DataError("Ukuran data terlalu besar untuk muat dalam gambar ini!")
    completed = False
    modified_bits = 0
    progress = 0
    progress_fraction = 1/total_bits
        
    for i in range(height):
        for j in range(width):
            pixel = img[i,j]
            for k in range(3):
                try:
                    x = next(bin_data)
                except StopIteration:
                    completed = True
                    break
                if x == '0' and pixel[k]%2==1:
                    pixel[k] -= 1
                    modified_bits += 1
                elif x=='1' and pixel[k]%2==0:
                    pixel[k] += 1
                    modified_bits += 1
                if progressBar != None:
                    progress += progress_fraction
                    progressBar.setValue(progress*100)
            if completed:
                break
        if completed:
            break

    written = imwrite(output_filepath,img)
    if not written:
        raise FileError("Gagal untuk mengambar file '{}'".format(output_filepath))
    loss_percentage = (modified_bits/encoding_capacity)*100
    return loss_percentage

#Extracts secret data from input image
def decode(input_filepath,password=True,progressBar=None):
    result,extracted_bits,completed,number_of_bits = '',0,False,None
    img = imread(input_filepath)
    if img is None:
        raise FileError("Gambar '{}' tidak ditemukan".format(input_filepath))
    height,width = img.shape[0],img.shape[1]
    for i in range(height):
        for j in range(width):
            for k in img[i,j]:
                result += str(k%2)
                extracted_bits += 1
                if progressBar != None and number_of_bits != None:
                    progressBar.setValue(100*(extracted_bits/number_of_bits))
                if extracted_bits == 32 and number_of_bits == None:
                    number_of_bits = int(result,2)*7
                    result = ''
                    extracted_bits = 0
                elif extracted_bits == number_of_bits:
                    completed = True
                    break
            if completed:
                break
        if completed:
            break
    try:
        return encrypt_decrypt(bin2str(result),password,'dec')
    except:
        raise PasswordError("Password salah!")
