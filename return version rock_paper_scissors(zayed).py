import random
def play():
	user = input("'r' for rock, 'p' for paper, 's' for scissors =>  ")
	computer = random.choice(['r', 'p', 's'])
	print("Computer\'s choice is :", computer)
	while user == computer:
		if user == 'r' and computer == 'r':
			return('match tie')
		elif user == 'p' and computer == 'p':
			return('match tie')
		elif user == 's' and computer == 's':
			return('match tie')
	while user != computer:
		if user == 'r' and computer == 'p':
			return('computer wins')
		elif user == 'r' and computer == 's':
			 return('user wins')
		elif user == 'p' and computer == 'r':
			return ('user wins')
		elif user == 'p' and computer == 's':
			return('computer wins')
		elif user == 's' and computer == 'r':
			return('computer wins')
		elif user == 's' and computer == 'p':
			return('user wins')
                
print(play())

