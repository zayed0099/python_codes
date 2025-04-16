'''
A very basic command-line chatbot that can respond to:
Time (What time is it?)
Simple math (What is 5 + 8?)
Tells jokes or motivational quotes
'''

from datetime import datetime
import random

# Start The Chat
print("Hi! I'm VINI7. The useless Chatbot developed by a useless teen")
print(random.choice([
    "What are you thinking today?", 
    "What brings you here today?", 
    "Welcome! What are you interested in?", 
    "How's your day going?"
]))
print('''Write 'Math' if you want to do a Math.
Write 'Time' if you want to know the Time.
Sad? Wanna hear a Joke? or maybe a Motivational Quote
to get some fake Dopamine which will last for 0.001s?
Then type "Yes")''')

# taking input from the user
user = input()
user_input = user.lower()

# time output 
now = datetime.now()
formatted = now.strftime("%H:%M, %d-%m-%y")

# function to say ehats the time
def timeee():
     somoy = "time"
     if somoy in user_input:
        var_somoy = "It's"
        somoy_to_print = var_somoy + " " + formatted
        print(somoy_to_print)

# Function for doing math
def calculation():
    dorkari_for_calculation = "math"
    if dorkari_for_calculation in user_input:
        print('''If you want to do a math please enter what math it is?
Currently it can perform Addition (+), Subtraction (-),
Multiplication (X) and Division (÷).
To add (+) two number -> Input 1
(-) two number -> Input 2
(X) two number -> Input 2
(÷) two number -> Input 2
               ''')
        calc_input = int(input())
        if calc_input in (1, 2, 3, 4):
            a = int(input("Give First number : "))
            b = int(input("Give Second number : "))
            if calc_input == 1:
                print(a + b)
            if calc_input == 2:
                print(a - b)
            if calc_input == 3:
                print(a * b)
            if calc_input == 4:
                print(a / b)

# Joke + motivation = jovation
jokes_and_jovation = [
    # Jokes
    "I told my computer I needed a break, and it froze.",
    "Parallel lines have so much in common… it’s a shame they’ll never meet.",
    "I ate a clock yesterday—it was time-consuming.",
    "My pillow and I are officially in a relationship.",
    "I’m on a seafood diet—I see food and I eat it.",
    "I would avoid the sushi… it’s a little fishy.",
    "I’m great at multitasking—I can waste time, be unproductive, and procrastinate all at once.",
    "My wallet is like an onion—opening it makes me cry.",
    "Why don’t skeletons fight? They don’t have the guts.",
    "I used to play piano by ear, but now I use my hands.",
    
    # Jovation (Motivational jokes for programmers)
    "Every bug you fix is just a misunderstood feature made right.",
    "Keep pushing—Git commit, Git better.",
    "If at first you don’t succeed, call it version 1.0.",
    "One day, your spaghetti code will become lasagna—with enough layers.",
    "Real devs don’t quit—they just debug life.",
    "404: Motivation not found? Refresh and try again.",
    "While (not successful): keep_coding()",
    "Even infinite loops end… when you believe in yourself.",
    "Stack overflowed? Just pop some hope and push forward.",
    "Your code might be messy, but so was the Big Bang."
]

def jovation():
    hmm = 'yes'
    if hmm in user_input:
        print(random.choice(jokes_and_jovation))


if "time" in user_input:
    timeee()
elif "math" in user_input:
    calculation()
elif "yes" in user_input:
    jovation()
else:
    confused_responses = [
    "Sorry... I'm too useless to understand that 😔",
    "Bruh I don't even know what that means.",
    "My brain.exe just crashed 🧠💥",
    "I just stare at the ceiling like a true dev...",
    "Try something else before I spiral into digital existentialism 💀"
]
    print(random.choice(confused_responses))

# print("dance dance dance yoooo")