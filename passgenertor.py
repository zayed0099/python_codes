import random

def password():
	List = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',  
 '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '#']
	password = random.choices(List, k = int(input("Enter the Vale of password length : ")))
	#print("The generated password is", password)
	combined_string = "".join(password)  
	print(combined_string)
print(password())
