from Cryptodome import *

#Class for encryption and decryption via RSA protocol
class RSA:
    def __init__(self,m):
        self.publickey=[]
        self.privatekey=[]
        self.p=0
        self.q=0
        self.m=m

# computes modExponentiate using pythons inbuilt pow() function.
    def modExponentiate(self,b,e,n):
        return pow(b,e,n)

#algorithm to find GCD of n & m
    def Euclid(self,n,m):
        if m%n==0:
            return n
        else:
            return self.Euclid(m%n,n)

#algorithm to find coefficient's of bezout's identity. Needed to find Modular Inverse.
    def ExtEuclid(self,n,m):
        if m%n==0:
            return 1,0,n
        else:
            x,y,d= self.ExtEuclid(m%n,n)
            x1= y-(m//n)*x
            y1= x
            return x1,y1,d

# algorithm to find the Modular inverse of a in base n. Raises an exception with a
# poor attempt at a Star Wars reference if the inverse doesn't exist
    def MInverse(self,a,n):
        b=self.ExtEuclid(a,n)
        if b[2]==1:
            return b[0]%n
        else:
            raise Exception("Sorry, these are not the numbers you are looking for")

#function to convert an integer s, into a list representation in the given base,
#with the most significant values to the left.
    def baseConvert(self,s,base):
        intList=[]
        count=0
        otherCount=0
        checker= base-1
        while s>checker:
            count=count +1
            otherCount= otherCount+1
            checker= checker + ((base-1)*(base**count))
        if count>0:
            for i in range(count):
                a=s%(base**otherCount)
                b=(s-a)//(base**otherCount)
                s=a
                otherCount=otherCount-1
                intList.append(b)
            intList.append(a)
        else:
            intList.append(s)
        return intList

# First calculates the value of numerical value of the message, then implements base
#convert to convert it to a list of integers.
    def stringToIntList(self,m,base):
        count=0
        total=0
        for i in m:
            a=ord(i)*256**count
            count=count+1
            total=total+a
        list=self.baseConvert(total,base)
        return list

#inverse of stringToIntList. Basically converts the list of integers back to their
#original string form.
    def intListToString(self,list,base):
        a=len(list)
        count=a-1
        largeNum=0
        oriString=""
        for i in range(a):
            value=list[i]*(base**count)
            largeNum=largeNum+value
            count=count-1
        correctList=self.baseConvert(largeNum,256)
        correctList.reverse()
        for i in correctList:
            b=chr(i)
            oriString=oriString+b
        return oriString

#generates 64-bit primes using a function from the Cryptodome module.
#I believe the function implements the millerRabin test
    def primegen(self):
        self.p=Util.number.getPrime(64,randfunc=None)
        self.q=Util.number.getPrime(64,randfunc=None)

#function to find the coPrime for any value a. Needed to create one
#half of the private key value.
    def coPrimeFinder(self,a):
        count=2
        while self.Euclid(count,a)!=1:
            count=count+1
        return count

#Generates both public and private keys
    def keygen(self):
        self.primegen()
        n = (self.p) * (self.q)
        a= ((self.p)-1)*((self.q)-1)
        e=self.coPrimeFinder(a)
        d=self.MInverse(e,a)
        self.publickey=[e,n]
        self.privatekey= [d,n]

#Generates both public and private keys based on DLN's test values
    def testerKeyGen(self):
        p=5277019477592911
        q=7502904222052693
        n =  p*q
        a= (p-1)*(q-1)
        e=self.coPrimeFinder(a)
        d=self.MInverse(e,a)
        self.publickey=[e,n]
        self.privatekey= [d,n]

#  Takes the message m, converts to a list of integers and encrypts each one using the
#public key. returns a list of encrypted numbers
    def encrypt(self):
        list=self.stringToIntList(self.m,self.publickey[1])
        encryptedList=[]
        for i in list:
            a=self.modExponentiate(i,self.publickey[0],self.publickey[1])
            encryptedList.append(a)

        return encryptedList

#Takes the list of encrypted numbers, decrypts each one using the private key and
#restores it to its original string format. Returns the original string
    def decrypt(self,y):
        partialDecryptedList=[]
        for i in y:
            a=self.modExponentiate(i,self.privatekey[0],self.privatekey[1])
            partialDecryptedList.append(a)
            b=self.intListToString(partialDecryptedList,self.privatekey[1])
        return b

#function to run the test code from values in #10
def testerCode():
    m="THE SECRET OF BEING BORING IS TO SAY EVERYTHING"
    DLNtest= RSA(m)
    DLNtest.testerKeyGen()
    a=DLNtest.encrypt()
    print(DLNtest.decrypt(a))

#function to input any message you want. Also uses random large primes
def inputCode():
    m=input("Insert your input message here:")
    RSAalgo= RSA(m)
    RSAalgo.keygen()
    a=RSAalgo.encrypt()
    print("Here's the message after encryption and decryption:")
    print(RSAalgo.decrypt(a))


testerCode()
inputCode()
