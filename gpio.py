"""
Knock-knock
"""
import time
import RPi.GPIO as GPIO
import airtag

# Configuration:
# DOORBELL: the GPIO pin connected to the doorbell trigger
DOORBELL = 10
# switches: the GPIO pins used to arm the tags. You can have more devices configured than this, but only the first len(switches) will be able to ring the doorbell
switches = [9, 11]
# leds: the GPIO pins connected to the LEDs indicating the tags are armed (the length of this should be the same as len(switches))
leds = [24, 25]
# Tolerance: Once the Airtag is less than MINIMUM_DISTANCE dBm away, the bell will ring
MINIMUM_DISTANCE = -60
# End configuration


states = list(map(lambda t: False, switches))
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
    states[switches.index(channel)] ^= True
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
    if rssi > MINIMUM_DISTANCE:
        index = tags.index(name)
        if index != -1 and index < len(states):
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
        GPIO.setup(switch, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.add_event_detect(switch, GPIO.FALLING,
                              callback=handle_switch, bouncetime=200)
    set_leds()
    print("GPIO configured")
    tags.extend(airtag.setup("keys"))
    print(f"Configured tags {tags}")
    airtag.start(handle_tag)
    GPIO.cleanup()


if __name__ == "__main__":
    main()
