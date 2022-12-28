"""
Knock-knock
"""
import time
import RPi.GPIO as GPIO
import airtag

DOORBELL = 10
switches = [9, 11]
leds = [24, 25]

states = [False, False]
tags = []

def set_leds():
    """
    Set the LEDs to the current state
    """
    print(f"Setting LEDs to {states}")
    for (channel, state) in zip(leds, states):
        GPIO.output(channel, GPIO.LOW if state else GPIO.HIGH)

def handle_switch(channel):
    """
    Handle the switch being depressed
    """
    print("Switch detected")
    states[switches.index(channel)] = True
    set_leds()

def ring_doorbell():
    """
    Ring the doorbell
    """
    print("Ding dong")
    GPIO.output(DOORBELL, GPIO.LOW)
    time.sleep(2)
    GPIO.output(DOORBELL, GPIO.HIGH)

def handle_tag(name, rssi):
    """
    Handle a report that a tag has been located
    """
    print(f"Tag {name} detected at {rssi}")
    if rssi > -40:
        index = tags.index(name)
        if index != -1:
            if states[index]:
                states[index] = False
                set_leds()                
                ring_doorbell()

def main():
    """
    The main application setup
    """
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(DOORBELL, GPIO.OUT)
    # High turns the doorbell off
    GPIO.output(DOORBELL, GPIO.HIGH)
    for led in leds:
        GPIO.setup(led, GPIO.OUT)
    for switch in switches:
        GPIO.setup(switch, GPIO.IN)
        GPIO.add_event_detect(switch, GPIO.RISING, callback=handle_switch)
    set_leds()
    print("GPIO configured")
    tags.append(airtag.setup("keys"))
    print(f"Configured tags {tags}")
    airtag.start(handle_tag)
    GPIO.cleanup()

if __name__ == "__main__":
    main()
