import random

def play():
	user = input("'r' for rock, 'p' for paper, 's' for scissors =>  ")
	computer = random.choice(['r', 'p', 's'])
	while user != computer:
		if user == 'r' and computer == 'r':
			print('try again')
		elif user == 'r' and computer == 'p':
			print('computer wins')
		elif user == 'r' and computer == 's':
			print ('user wins')
		elif user == 'p' and computer == 'r':
			print ('user wins')
		elif user == 'p' and computer == 'p':
			print('try again')
		elif user == 'p' and computer == 's':
			print('computer wins')
		elif user == 's' and computer == 'r':
			print('computer wins')
		elif user == 's' and computer == 'p':
			print('user wins')
		elif user == 's' and computer == 's':
			print('try again')

print(play())

