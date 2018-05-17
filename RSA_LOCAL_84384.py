# -*- coding: utf-8 -*-
"""
Created on Tue Apr 17 22:15:51 2018

@author: EslamAkrm
"""
import time
import random
import os



def EEA(r0, r1): #r0 > r1
    s0, t0, s1, t1 = [ 1, 0, 0, 1 ]
    while r1 != 0:
        q = r0 / r1
        r1, r0 = [ r0%r1, r1 ]
        s0, t0, s1, t1 = [ s1 - q*s0, t1 - q*t0, s0, t0 ]
    return [ r0, t1, s1 ] #[gcd , inverse of r1 , ]
    
def modularInverse(mod, a):
    gcd, s1 , inverse = EEA(mod, a)
    
    return None if gcd != 1 else (inverse % mod)
    

def RSAparameters():
    p = primeNumberGenerator()
    q = primeNumberGenerator()
    n = p*q
    minPrivateKeyBitLen = int(0.3*(len(bin(n))-2))
    numberOfPrimes = (p-1)*(q-1)
    e,d = selectPrimeExponent(numberOfPrimes,minPrivateKeyBitLen)
    return p,q,e,d
   
def squareAndMultiply(x,e,mod): # x^e % mod
    e = [int(i) for i in list(bin(e)[3:])] # calculate binary respresentation removing '0b' notation and the first 1 in binary form
    base = x
    for i in e:
        x = (x**2) % mod
        if i == 1: #h==1
            x = (x*base) % mod
    return x
    
def encryptMessage(plainText,publicKey):
    # y = x^e mod n
    n,e = publicKey
    return squareAndMultiply(plainText,e,n)
    
def decryptMessage(cipherText,privateKey,p,q,useCRT = False):
    # x = y^d mod n    d is the privateKey
    
    if useCRT == False:
        n = q*p
        return squareAndMultiply(cipherText,privateKey,n)
    else:
        return decryptCRT(cipherText,privateKey,p,q)

def decryptCRT(cipherText,privateKey,p,q):
    yp , yq = [cipherText % p , cipherText % q]
    dp ,dq = [privateKey % (p-1) , privateKey % (q-1)]
    xp , xq = [squareAndMultiply(yp,dp,p) , squareAndMultiply(yq,dq,q)]
    cp , cq = [modularInverse(p,q%p),modularInverse(q,p%q)]
    
    x = ((q*cp*xp) + (p*cq*xq)) % (p*q)
    return x

def Miller_RabinTest(primeCandidate , s):
    for i in range(1,s): # s at least 2
        a = random.SystemRandom().randint(2,primeCandidate-2) 
        r=primeCandidate-1
        u=1
        while r % 2 == 0: #get the value of r and u
            u+=1
            r /= 2
        z = squareAndMultiply(a,r,primeCandidate)
        if z != 1 and z != primeCandidate-1:
            for j in range(1,u):
                z = (z**2) % primeCandidate
                if z == 1:
                    return False  #composite
            if z != primeCandidate-1:
                return False  #composite
    return True   #likely prime
    
def primeNumberGenerator():
     p = int(os.urandom(64).encode('hex'),16)
     while not Miller_RabinTest(primeCandidate=p ,s=40) :  #512 bit random number #512 bit random number
         p = int(os.urandom(64).encode('hex'),16)
     return p


def selectPrimeExponent(limit,minPrivateKeyBitLen):
    d = None
    while d == None:
        e = int(random.randint(1,limit-1))
        d = modularInverse(limit,e)
        if d != None:
            if len(bin(d))-2 < minPrivateKeyBitLen:
                d = None
    return e,d


def stringToAscii(s):
    return int(''.join((str(ord(c)+100)) for c in s)) # +100 to make all numbers have 3 digits


def asciiToString(a):
    x = [i for i in str(a)]
    res = []
    i=0
    while i < len(x)-2:
        a = [x[i],x[i+1],x[i+2]]
        res.append(''.join(a))
        i+=3
    res = [int(c)-100 for c in res]
    return ''.join(chr(i) for i in res)

def partitioningPlainText(text): # too long string cause undeterministic behavior (string over 102 char)
     length=100;                   
     return [text[i:i+length] for i in range(0, len(text), length)]




######################  finding parameter ############################  
useCRT = raw_input("use chineese remainder theorem ? (y,n)\n" )
useCRT = True if (useCRT == 'y'or useCRT == 'Y') else False
a = time.clock()
p,q,e,d = RSAparameters()
print "time to find parameters = " + str(time.clock()-a)
n = p*q
publicKey = [n,e]
privateKey = d
print "public key :"
print "n = " + str(n)
print "e = " + str(e)
print "private key = " + str(d)

print "#################################################################"
#####################################################################

###################### string To ASCII ############################ 
#a = time.clock()
Input = raw_input("Enter the PlainText : ")
partitionedInput = partitioningPlainText(Input)
asciiInput = [stringToAscii(aa) for aa in partitionedInput ]
#print "stringToAscii Time ="+ str(time.clock()-a)
#####################################################################


###################### Encryption ############################ 
a = time.clock()
cipherText = [encryptMessage(aa,publicKey) for aa in asciiInput ]
print "ecryption Time = " + str(time.clock()-a)
print "#################################################################"
#####################################################################

###################### Dencryption ############################ 
a = time.clock()
plainText = [decryptMessage(aaa,privateKey,p,q,useCRT=useCRT) for aaa in cipherText]
print "ecryption Time = " + str(time.clock()-a)
print "#################################################################"
#####################################################################

output = [asciiToString(z) for z in plainText]
print "PlainText after decryption :" + ''.join(output)

