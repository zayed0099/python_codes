marks = [55, 34, 29, 40, 35]
total_number = sum(marks)
subject_number = len(marks)
average = total_number/subject_number
        
#grading system
def grade(average):
	if average >= 70:
		print ("Your Grade is 'A'")
	elif average >= 60 :
		print ("Your Grade is 'B'")
	elif average >= 50 :
		print ("Your Grade is 'C'")
	elif average < 50:
		print ("Your Grade is 'F'" )
        
#remarking system
def remarks(average):
	if average >= 70:
		print ("Congratulations, Hard work really paid off. <Promoted>")
	elif average >= 60:
		print ("Great,  You are close to highest grade. <Promoted>")
	elif average >= 50:
		print ("Good, But attention to studies are needed. <Promoted>")
	elif average < 50:
		print ("Sorry, You are not qualified for Promotion" )
        
        
print("Your average number is:", average)
grade(average)
remarks(average)
        