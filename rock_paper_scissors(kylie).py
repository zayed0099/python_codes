import random
def rps():
	computer = random.choice["r", "p", "s"]
	user = input("'r' for rock, 'p' for paper, 's' for scissors => ")
	print("Computer\'s choice is :", computer)
	# r>s, s>p, p>r
	if (user == 'r') and (computer == 's') or \
	(user == 's') and (computer == 'p') or \
	(user == 'p') and (computer == 'r'):
		return("user wins")
	elif (user == computer):
		return("match Tie")
	else:
		return("computer wins")

rps()