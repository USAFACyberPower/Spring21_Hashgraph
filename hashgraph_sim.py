#!/usr/bin/env python

__author__ = "Brett Martin"

"""
===========================================================
 Name: ECE 463, Fall 2019/Spring 2020
 Created by: C1C Brett Martin
 Section: M3/4
 Project: Cyber Power Capstone
 Purpose: Hashgraph Algorithm Simulator
 Documentation: See the Github README journal for all references. 
    I asked C1C Sears Schulz for help with understanding PKI.
===========================================================
"""

import datetime
import nacl.encoding
import nacl.signing
import pickle
import os
import random

class Transaction:

    def __init__(self, data):
        self.data = data


class Event:
    """
    A single event created by a member in the graph.

    """

    def __init__(self, owner, timestamp, transactions=[]):
        '''
        Initializes an event object with all necessary information and signs it with the owner member's signature.

        Args:
            owner (class Member): Member which initialized the event.
            transactions (list): Contains information about the transactions (such as voltage or current data for certain relays)

        '''
        self.owner = owner
        self.transactions = transactions
        self.timestamp = timestamp
        self.hash = None


class Member:
    """
    Emulates a node or computer in the network. Referred to as a 'member' in the white paper.

    """

    def __init__(self, name):
        '''
        Args:
            name (string): Name of the member.

        '''
        self.name = name
        self.events = []
        self.signing_key = (nacl.signing.SigningKey.generate())
        # Keys should be generated on each node, not on a server-side script like this. For simulation purposes, we'll include the keys in the Member class.

    def sign_event_func(self, event):
        '''
        Uses Pickle to convert the event object to type byte. Signs the byte-type event created or agreed upon by the member and generates a verify key and a hex encoded verify key.

        Args:
            event (object Event): Event object to be signed by the member.

        Returns:
            (tuple): Contains the signed event, verify key, and the hex encoding of the key.

        '''
        obj_string = pickle.dumps(event)
        signed = self.signing_key.sign(obj_string)
        verify_key = self.signing_key.verify_key
        verify_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        return (signed, verify_key, verify_hex)

    def verify_key_func(self, event):
        '''
        Verifies the key by checking the hex encoded verify key with the signed byte-type event.

        Args:
            event (class Event): The event to be verified.

        Returns:
            (int): Value -1 for bad signature, 0 for successful verification.

        '''
        verify_key = nacl.signing.VerifyKey(event.hash[2], encoder=nacl.encoding.HexEncoder)
        try:
            verify_key.verify(event.hash[0])
        except nacl.exceptions.BadSignatureError:
            return -1
        return 0

    def debug_member(self):
        '''
        Prints debug information related to the Member to include Name, Events, and Key.

        '''

        print("Name: {}\nEvents: {}\nKey: {}\n".format(self.name, self.events, self.signing_key.sign))
        try:
            for i in self.events:
                print("Event details:\nOwner:\t\t {}\nTransaction(s):\t {}\nTimestamp:\t {}\nHash:\n\t Signed:\t\t {}...\n\tVerify Key: \t\t{}\n\tVerify Key Hex: \t{}\n".format(i.owner.name, i.transactions, i.timestamp, i.hash[0][0:180], i.hash[1], i.hash[2]))
        except AttributeError:
            print("No events exist for Member {}\n".format(self.name))

        run_test = input("Run key verification test on member {}? (y/n)". format(self.name))

        if run_test == 'y':
            self.events.append(Event(type(self), None, ["ECE463", "ECE464"]))
            test_event = self.events.pop()
            test_event.hash = self.sign_event_func(test_event)
            if self.verify_key_func(test_event) == 0:
                print("Test successful\n\n")
            else:
                print("Test unsuccessful\n\n")
        else:
            print("Exiting test...\n\n")

        return


class HashGraphStruct:
    """
    Creates a simulated network (or graph) to test the hashgraph function as it applies to the captone project by simply initializing an empty list of members.
S
    """

    def __init__(self, members=None):
        '''
        Args:
            members (class Member): The empty, initialized list of members.

        '''
        self.members = []
        self.active = True

    def sampling_simulation_safe(self, member):
        event_time = datetime.datetime.now()
        new_sample = [{"IA":random.randint(30,50), "IB":random.randint(30,50), "IC":random.randint(30,50)}, {"VA":random.randint(20,40), "VB":random.randint(20,40), "VC":random.randint(20,40)}]
        new_event = Event(member, event_time, new_sample)
        new_event.hash = member.sign_event_func(new_event)
        member.events.append(new_event)

        print("\nEvent created by {}\n\n".format(member.name))

        for i in self.members:
            if i != member:
                i.events.append(new_event)
                if i.verify_key_func(i.events[-1]) == 0:
                    print("Event verified by {}!\n\n".format(i.name))
                else:
                    print("Event could not be verified by {}\n\n".format(i.name))

        return

    def sampling_simulation_corrupt(self, member, corr_member):
        event_time = datetime.datetime.now()
        new_sample = [{"IA":random.randint(30,50), "IB":random.randint(30,50), "IC":random.randint(30,50)}, {"VA":random.randint(20,40), "VB":random.randint(20,40), "VC":random.randint(20,40)}]
        new_event = Event(member, event_time, new_sample)
        new_event.hash = member.sign_event_func(new_event)
        member.events.append(new_event)

        print("\nEvent created by {}\n\n".format(member.name))
        
        corr_sample = [{"IA":random.randint(30,50), "IB":random.randint(30,50), "IC":random.randint(30,50)}, {"VA":random.randint(20,40), "VB":random.randint(20,40), "VC":random.randint(20,40)}]
        corr_event = Event(member, event_time, corr_sample)
        corr_event.hash = corr_member.sign_event_func(corr_event)

        print("{}'s event manipulated\n\n".format(corr_member.name))

        for i in self.members:
            if i != member:
                if i != corr_member:
                    i.events.append(new_event)
                    if i.verify_key_func(i.events[-1]) == 0:
                        print("Event verified by {}!\n\n".format(i.name))
                    else:
                        print("Event could not be verified by {}\n\n".format(i.name))
                else:
                    i.events.append(corr_event)
                    try:
                        i.events[-1].hash[1].verify(i.events[-1])
                    except:
                        print("Event could not be verified by2 {}\n\n".format(i.name))
                
        return

    def event_dump(self):
        '''
        Clears the event list for each member in the graph.

        '''

        for i in self.members:
            i.events.clear()

        return


# Creates the simulation of the network (or graph) in which the nodes will reside
network = HashGraphStruct()

# Creates four example nodes IAW the example from the Hashgraph Examples White Paper
alice = Member("Alice")
bob = Member("Bob")
carol = Member("Carol")
dave = Member("Dave")

# Adds each member to the network (or graph)
network.members.extend([alice, bob, carol, dave])

os.system('clear')

while(network.active):

    mode = input("Select mode (debug, simulate, corrupt, dump, clear, quit): ")

    if mode == "debug":
        print("\n")
        for i in network.members:
            i.debug_member()
    elif mode == "simulate":
        network.sampling_simulation_safe(alice)
    elif mode == "corrupt":
        network.sampling_simulation_corrupt(alice, carol)
    elif mode == "dump":
        network.event_dump()
    elif mode == "clear":
        os.system('clear')
    elif mode == "quit":
        network.active = False
    else:
        print("{} is not a valid mode".format(mode))
