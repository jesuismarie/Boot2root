import time
import turtle

with open("turtle", "r") as f:
	lines = f.readlines()

screen = turtle.Screen()
t = turtle.Turtle()
t.speed(0)

for line in lines:
	line = line.strip()
	if not line:
		time.sleep(4)
		t.clear()
		t.penup()
		t.home()
		t.pendown()
		continue

	parts = line.split()
	if parts[0].lower() == "tourne":
		direction = parts[1].lower()
		angle = int(parts[3])
		if direction == "gauche":
			t.left(angle)
		elif direction == "droite":
			t.right(angle)

	elif parts[0].lower() == "avance":
		distance = int(parts[1])
		t.forward(distance)

	elif parts[0].lower() == "recule":
		distance = int(parts[1])
		t.backward(distance)

turtle.done()
