# Hardware

## Requirements
To build this into an actual doorbell like the one I built, you will need:
   * Raspberry Pi 3 A+
   * Electrocookie solderable mini breadboard 
   * A Teknet wireless doorbell
   * 2x red LEDs
   * 2x 220 Ohm resistors
   * 1x IDC breakout helper (5x2)
   * 2x tactile SPDT switch
   * A few IO header pins
   * 5x 2M screws (4mm or so would be fine)
   * The usual prototyping stuff - soldering equipment, jumper cables
   * Some kind of 3d printing setup

## The doorbell
Plug in the doorbell and test it first, then disassemble the remote control and detach the PCB. Remove the battery.
Assuming you have the same model as me, then placing the PCB battery side down, with the antenna at the top left, there are 4 ports at the top left. The top of these is ground, the bottom requires +3.3v. I attached a header to these so I could easily plug it in to the primary circuit. The only tricky part was the trigger - keeping the same orientation, I soldered a wire to the bottom-left pin of the tactile switch. You can test this by reinstalling battery and jumping this pin directly to the +3.3v pin. If the doorbell rings, you're in good shape.

## The primary circuit
I attached the IDC breakout to the centre of the board, *on the reverse side*. This leaves more space for wiring on the top. The intention is to use 2x4 (not 2x5!) of the pins in the middle of the PI GPIO header to provide +3.3V, GND and 4 IO ports to the board. I then attached the switches and LEDs either side, and connected them to the GPIO pins (the LEDs also require ~220 Ohm resistors). Finally, I attached 3 single header pins to the reverse side so that I could link the primary circuit to the doorbell PCB.

I would liked to have used IDC ribbon connectors to connect the GPIO and breadboard, but it's not possible to connect a 2x5 IDC connector to the *middle* of the pi's GPIO header. A riser might have helped - that would have made the case a lot shorter.

## The case
The case directory contains some STL files for printing a case for a Raspberry Pi 3+ with 2 buttons and quite a lot of space for wiring. There's a base (adapted from https://www.thingiverse.com/thing:3243466), a case with a lot more headroom, and a 3-piece button with a letter cut into the top.

## Assebly
Print the case and 2 buttons. Assemble the buttons and insert into the holes. Screw the primary circuit board onto the 4 shorter risers, holding the buttons in place. They should click the tactile switches when depressed. Then screw the doorbell transmitter onto the longer riser (the other one is just a rest). Finally, attach the Pi to the bottom of the case and clip the halves together.

## Configuration
A sample systemd service is provided in doorbell.service. It assumes that you have already checked out the code in ~pi/knock-knock and installed the prerequisites, and that your default user is called `pi`. You will also need to create the `keys` file by running the decryptor utility on a Mac paired with the Airtag(s) in question

You can edit the tolerance required to ring the bell (ie the distance the Airtag must be to the receiver) and the IO pins involved at the top of the gpio.py file.