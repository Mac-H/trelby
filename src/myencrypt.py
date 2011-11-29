#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import util
import misc

import os
import wx

from hashlib import sha256
from Crypto.Cipher import AES

# DO NOT CHANGE! - fixed 8 byte ID
# Used as part of salt in encrypted files
PROGID = "79184SLT"

# generate an 8 byte random salt - 4*8 bits of entropy.
def randomsalt():
    return sha256(os.urandom(16)).hexdigest()[0:8]

# A wrapper around hashlib's SHA256. Returns the digest.
def getHash(stream):
    return sha256(stream).digest()

# Converting a user input password/phrase to 256 bit key
def getKeyFromPassword(password, randomsalt):
    salt = PROGID + randomsalt
    return sha256(salt + password).digest()


# AES (256 bit key) in CFB mode
# Stream - arbitrary length
# key - 16,24,32 bytes. We're using sha256 so 32.
# iv - initialization vector
# returns - ciphertext stream : length to closest mod16 ceiling + 16.
def encryptData(stream, key, iv):
    # to encrypt a stream, we also store it's length as a string..
    lenstr = "%16d" % len(stream)
    # .. append it to the beginning ..
    plaintext = lenstr + stream
    # .. and bring the size to mod 16
    diff = 16 - (len(plaintext) % 16)
    plaintext += " " * diff
    #finally encrypt this and return!
    enc = AES.new(key, AES.MODE_CFB)
    return enc.encrypt(plaintext)

def decryptData(stream, key, iv):
    dec = AES.new(key, AES.MODE_CFB)
    plainstream = dec.decrypt(stream)
    n = int(plainstream[0:16])
    return plainstream[16: 16 + n]


def decryptFile(fileName, frame):
    s = util.loadFile(fileName, frame)
    if s == None:
        return None
    # Minimum header length = 56 bytes.
    # encryptData will add a minimum of 32 bytes padding for empty string
    # So the stream can be a minimum of 88 bytes
    if len(s) < 88:
        wx.MessageBox("Something is wrong with the file encryption header! File is too short to import.",
            "Error", wx.OK, frame)
        return None

    header = s[0:56]
    ciphersp = s[56:]

    if len(ciphersp)%16 != 0:
        wx.MessageBox("Something is wrong with the encrypted screenplay data! The file was either modified, or truncated.",
            "Error", wx.OK, frame)
        return None

    commonsalt = header[0:8]
    randomsalt = header[8:16]
    keyintegrityhash = header[16:24]
    spintegrityhash = header[24:56]

    if commonsalt != PROGID:
        wx.MessageBox("Error: Encryption salt mismatch!", "Error",
                      wx.OK, frame)
        return None
    salt = commonsalt + randomsalt

    correctpw = False
    pwdlg = misc.PasswordInputDlg(frame, "Enter the password for this file",
            "Encrypted file")
    while not correctpw:
        pwdlg.SetValue("")
        if pwdlg.ShowModal()==wx.ID_OK:
            password =  pwdlg.input
            key = getHash(salt + password)
            keyhash = getHash(salt + key)[0:8]
            if keyhash != keyintegrityhash:
                #bad password
                wx.MessageBox("Wrong Password. Try again!\n\n", "Bad password",
                              wx.OK, frame)
            else:
                correctpw = True
        else:
            return None

    s = decryptData(ciphersp, key, salt)
    calculatedhash = getHash(PROGID + randomsalt + s)
    if calculatedhash != spintegrityhash:
        wx.MessageBox("File integrity mismatch. Look out for corrupt data",
            "Integrity Error", wx.OK, frame)
    return s, key, randomsalt

def encryptScreenplay(sptext, randomsalt, key):
    salt = PROGID + randomsalt
    integritysphash = getHash(salt + sptext)
    integritykeyhash = getHash(salt + key)[0:8]
    header = salt + integritykeyhash + integritysphash
    ciphertext =  encryptData(sptext, key, salt)
    filetext = header + ciphertext
    return filetext


