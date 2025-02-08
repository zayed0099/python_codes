import random

def guess(x):
    random_number = random.randint(1,x)
    guess = 0   #to declare that variable 'guess' starts at '0' and its initial value is '0'
    while guess != random_number: #[still confused about it (cleared)] reason :- #while loop saying as long as the feedback is not equal to 'c', the loop should follow the code below
        guess = int(input(f"guess a number between 1 and {x} : "))
        if guess < random_number:
            print ('number too low')
        elif guess > random_number:
            print('number too high')
        elif guess == random_number:
            print ("congratulations, you successfully predicted the right number")


def computer_guess(x):
    low = 1
    high = x
    feedback = ''
    while feedback != 'c':   #while loop saying as long as the feedback is not equal to 'c' or theoretically 'correct', the loop should follow the code below
        guess = random.randint(low, high)
        feedback = input(f'Is {guess} too high (H), too low (L), or correct (C))?? ').lower()
        if feedback == 'h':
        	high = guess - 1
        elif feedback == 'l':
        	low = guess + 1
        elif feedback == 'c':
        	print('Booyah! The Computer guessed our number correctly....')
    
                    #note :- in both programs computer is doing nothing. everything is just the logic we set.


# unnecessary codes to make this a proper game
print("Hey! Let\'s play a game? Shall we?")
print('''At first I will try to guess the number you have in your mind. \n After that, You will try to guess the number I have in my mind. \n Let's start the game....''')
print('---------------------- \n     range (1 - 10)     \n----------------------')
print('<GAME STARTS>')   
print ('                      ') 
computer_guess(10)
print ('                      ') 
print ('                      ') 
print("Now it's your turn to guess")
guess(10)       
                
        


