import random

def password():
	List = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',  
 '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '#']
	special_characters = ['!', '@', '$', '%', '^', '&', '*', '+', '#']
	
	password1 = random.choices(List, k = 100) #'k' is used to define the length of the password
	password2 = random.choices(special_characters, k = 25)
	# combined_string = "".join(password1)
	# combined_string2 = "".join(password2)  
	
	sumed = password1 + password2
	password_gen = random.choices(sumed, k = int(input("Enter the Value of password length : ")))
	password = "".join(password_gen)
	print("The generated password is : ", password)
	return ("The password generated should be used only once")
print(password())
