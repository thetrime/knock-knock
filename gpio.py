"""
Knock-knock
"""
import time
import RPi.GPIO as GPIO
import airtag

DOORBELL = 10
switches = [9, 11]
leds = [24, 25]

state = [False, False]
tags = []

def set_leds():
    """
    Set the LEDs to the current state
    """
    for i in range(len(state)):
        GPIO.output(leds[i], GPIO.HIGH if state[i] else GPIO.LOW)

def handle_switch(channel):
    """
    Handle the switch being depressed
    """
    state[switches.index(channel)] = True
    set_leds()

def ring_doorbell():
    """
    Ring the doorbell
    """
    GPIO.output(DOORBELL, GPIO.LOW)
    time.sleep(2)
    GPIO.output(DOORBELL, GPIO.HIGH)

def handle_tag(name, rssi):
    """
    Handle a report that a tag has been located
    """
    if rssi > -40:
        index = tags.index(name)
        if index != -1:
            if state[index]:
                ring_doorbell()
                state[index] = False
                set_leds()

def main():
    """
    The main application setup
    """
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(DOORBELL, GPIO.OUT)
    for led in leds:
        GPIO.setup(led, GPIO.OUT)
    for switch in switches:
        GPIO.setup(switch, GPIO.IN)
        GPIO.add_event_detect(switch, GPIO.RISING, callback=handle_switch)
    tags.append(airtag.setup("keys"))
    airtag.start(handle_tag)
    GPIO.cleanup()

if __name__ == "__main__":
    main()
