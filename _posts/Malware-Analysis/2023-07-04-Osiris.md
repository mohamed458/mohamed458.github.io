---
title: "Osiris"
classes: wide
header:
  teaser: /assets/images/CTF/Osiris/logo.jpg
ribbon: DodgerBlue
description: "RE CSC CTF "
categories:
  - CTF
toc: true
---

### About Challenge : 

| Language  | Platform             | Difficulty | Quality | Arch |
| --------- | -------------------- | ---------- | ------- | ---- |
| Assembler | Windows 2000/XP      | 1.0        | 4.0     | x86  |
 

### Analysis :

when we run the Challenge  and write any thing it will pop this 

![](/assets/images/CTF/Osiris/WrongKeyCmd.PNG)

so we will search for this text in IDA pro we will see this function 

![](/assets/images/CTF/Osiris/mainfunction.PNG)

you can see there is function (0x401100) which take our input and according the return, validate the flag you enter .you can found two string which cross to good , bad input.we will dive into this function to see how it work 

![](/assets/images/CTF/Osiris/function401100.PNG)

the first screen to this function we will see 41 conditions which validate every char you had enter . you can found every condition has some operation like RotateTORight , RotatToLift and XORing .

I split this conditions and made script which bruteforce every char in flag   

```python
def __ROL1__(value, shift):
    shift %= 8  # Ensure shift is within the range of 0-15
    return ((value << shift) & 0xFF) | (value >> (8 - shift))
	
def __ROR1__(value, shift):
    shift %= 8  # Ensure shift is within the range of 0-15
    return (value >> shift) | ((value << (8 - shift)) & 0xFF)
a1 = [0] * 42

# Condition 0
for char0 in range(0x20, 0x7f):

    if __ROR1__(__ROL1__(int(hex(char0), 16), 48), 51) == 0xA8:
        a1[0] = char0
        print (char0)
        break

# Condition 1
for char1 in range(0x21, 0x7f):
    if __ROL1__(__ROL1__(char1, 16), 15) == 0xA3:
        a1[1] = char1
        break

# Condition 2
for char2 in range(0x21, 0x7f):
    if (__ROL1__(char2, 68) ^ 0x3A) == 14:
        a1[2] = char2
        break

# Condition 3
for char3 in range(0x21, 0x7f):
    if __ROR1__(char3 ^ 0x43, 47) == 12:
        a1[3] = char3
        break

# Condition 4
for char4 in range(0x21, 0x7f):
    if __ROR1__(char4 ^ 0xC, 47) == 0xBC:
        a1[4] = char4
        break

# Condition 5
for char5 in range(0x21, 0x7f):
    if (__ROL1__(char5, 20) ^ 0x11) == 84:
        a1[5] = char5
        break

# Condition 6
for char6 in range(0x21, 0x7f):
    if __ROL1__(char6 ^ 0x12, 42) == 0xA5:
        a1[6] = char6
        break

# Condition 7
for char7 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char7, 56), 68) == 83:
        a1[7] = char7
        break

# Condition 8
for char8 in range(0x21, 0x7f):
    if __ROR1__(char8 ^ 0x38, 19) == 97:
        a1[8] = char8
        break

# Condition 9
for char9 in range(0x21, 0x7f):
    if (__ROR1__(char9, 67) ^ 0x1F) == 121:
        a1[9] = char9
        break

# Condition 10
for char10 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char10, 38), 60) == 0xD7:
        a1[10] = char10
        break

# Condition 11
for char11 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char11, 51), 51) == 49:
        a1[11] = char11
        break

# Condition 12
for char12 in range(0x21, 0x7f):
    if __ROL1__(__ROL1__(char12, 28), 21) == 0xCC:
        a1[12] = char12
        break

# Condition 13
for char13 in range(0x21, 0x7f):
    if __ROR1__(char13 ^ 0x3A, 42) == 89:
        a1[13] = char13
        break

# Condition 14
for char14 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char14, 16), 42) == 94:
        a1[14] = char14
        break

# Condition 15
for char15 in range(0x21, 0x7f):
    if __ROR1__(__ROL1__(char15, 48), 24) == 48:
        a1[15] = char15
        break

# Condition 16
for char16 in range(0x21, 0x7f):
    if (__ROR1__(char16, 39) ^ 0x20) == 0xCA:
        a1[16] = char16
        break

# Condition 17
for char17 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char17, 35), 43) == 125:
        a1[17] = char17
        break

# Condition 18
for char18 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char18, 19), 62) == 35:
        a1[18] = char18
        break

# Condition 19
for char19 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char19, 58), 12) == 0xCC:
        a1[19] = char19
        break

# Condition 20
for char20 in range(0x21, 0x7f):
    if (__ROL1__(char20, 13) ^ 0x13) == 0xB5:
        a1[20] = char20
        break

# Condition 21
for char21 in range(0x21, 0x7f):
    if __ROR1__(char21 ^ 0x27, 21) == 0xA0:
        a1[21] = char21
        break

# Condition 22
for char22 in range(0x21, 0x7f):
    if (char22 ^ 0x33) == 97:
        a1[22] = char22
        break

# Condition 23
for char23 in range(0x21, 0x7f):
    if (__ROR1__(char23, 38) ^ 0x19) == 0xC0:
        a1[23] = char23
        break

# Condition 24
for char24 in range(0x21, 0x7f):
    if __ROL1__(char24 ^ 0x1B, 34) == 0xA0:
        a1[24] = char24
        break

# Condition 25
for char25 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char25, 36), 44) == 95:
        a1[25] = char25
        break

# Condition 26
for char26 in range(0x21, 0x7f):
    if (char26 ^ 0x79) == 14:
        a1[26] = char26
        break

# Condition 27
for char27 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char27, 20), 10) == 26:
        a1[27] = char27
        break

# Condition 28
for char28 in range(0x21, 0x7f):
    if (__ROL1__(char28, 69) ^ 0x3A) == 0xBC:
        a1[28] = char28
        break

# Condition 29
for char29 in range(0x21, 0x7f):
    if (__ROL1__(char29, 18) ^ 0x3F) == 0xE3:
        a1[29] = char29
        break

# Condition 30
for char30 in range(0x21, 0x7f):
    if __ROL1__(char30 ^ 0x33, 46) == 27:
        a1[30] = char30
        break

# Condition 31
for char31 in range(0x21, 0x7f):
    if __ROL1__(__ROL1__(char31, 39), 44) == 27:
        a1[31] = char31
        break

# Condition 32
for char32 in range(0x21, 0x7f):
    if (__ROR1__(char32, 33) ^ 0x19) == 1:
        a1[32] = char32
        break

# Condition 33
for char33 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char33, 38), 60) == 91:
        a1[33] = char33
        break

# Condition 34
for char34 in range(0x21, 0x7f):
    if (char34 ^ 0x3D) == 14:
        a1[34] = char34
        break

# Condition 35
for char35 in range(0x21, 0x7f):
    if __ROR1__(char35 ^ 0x3E, 19) == 97:
        a1[35] = char35
        break

# Condition 36
for char36 in range(0x21, 0x7f):
    if __ROL1__(__ROR1__(char36, 35), 24) == 0xEB:
        a1[36] = char36
        break

# Condition 37
for char37 in range(0x21, 0x7f):
    if __ROR1__(__ROL1__(char37, 49), 55) == 0xB9:
        a1[37] = char37
        break

# Condition 38
for char38 in range(0x21, 0x7f):
    if __ROR1__(__ROR1__(char38, 0x2b), 0xb) == 204:
        a1[38] = char38
        break

# Condition 39
for char39 in range(0x21, 0x7f):
    if  char39 ^ 0xE ^ 0x3d == 0x4b:
        a1[39] = char39
        break

# Condition 40
for char40 in range(0x21, 0x7f):
    if  char40 ^ 0x1E ^ 0x29  == 0:
        a1[40] = char40
        break

# Condition 41
for char41 in range(0x21, 0x7f):
    if __ROR1__(__ROL1__(char41, 12), 10) == 0xf5:
        a1[41] = char41
        break

print(a1)
 # Example list of numbers

characters = [chr(num) for num in a1]  # Convert numbers to characters
print (characters)

sentence = ''.join(characters)

print(sentence)
```

![](/assets/images/CTF/Osiris/flag.PNG)
FLAG : EGCERT{533_1f_y0u_d353Rv3_wh47_c0m35_n3x7}
