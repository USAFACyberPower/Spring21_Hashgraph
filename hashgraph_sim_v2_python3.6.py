#!/usr/bin/env python

__author__ = "Brett Martin"
__edited__ = "Jelani Washington"
#need to install Pynacl by "pip install pynacl"
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
import pdb
import datetime
import time
import nacl.encoding
import nacl.signing
import pickle
import os
import random
import threading 	# For simulation purposes: will allow multiple nodes to run at once

SIM = True

hg_nodes = ["421-C", "451-A", "421-D"]
N = len(hg_nodes)
current_node = 0
current_node_name = hg_nodes[current_node]
rand_node = 1


class Network:

	def __init__(self):
		self.nodes = []
		self.active = True

	def init_nodes(self, new_nodes):
		'''
		SIM: Adds all of the nodes in hg_nodes to the simulated Network.

		Args:
			new_nodes (List): List containing the names (String) of each simulated Node.

		'''

		for i in new_nodes:
			self.nodes.append(Node(i))
		return

	def node_set_network(self, nw):
		'''
		Assigns each Node to the simulated Network and generates the initial, empty Event to start the Hashgraph.

		Args:
			nw (object Network): The simulated Network.

		'''

		for i in self.nodes:
			i.network = nw
			for j in self.nodes:
				i.hg[j.name] = [] 	# Creates empty list for each node that will contain all events
			i.create_event()		# Create empty init Event for each Node
		return

	def print_nodes(self):
		'''
		Prints all of the Nodes currently connected to the simulated Network.

		'''

		print("\nNodes on network: {}\n".format(self))
		for i in self.nodes:
			print("Node:\n {}\n {}\n".format(i.name, i.signing_key.sign))
		return


class Event:

    def __init__(self, time, data, self_parent, other_parent, self_parent_event_hash, other_parent_event_hash, node):
        self.timestamp = time
        self.data = data
        self.sp = (self_parent, self_parent_event_hash)
        self.op = (other_parent, other_parent_event_hash)
        self.round = None
        self.witness = None #True data is verfied, False data is unverified, None data does not exist
        self.node_name = node

    def check_supermajority(self, node_list, event, thresh_events):
        ''' 
		does it return node_list or some measure of supermajority?
		'''
        #pdb.set_trace()
        if event.witness:#event->self
            #pdb.set_trace()
            if self.node_name not in node_list:#event->self
                node_list.append(self.node_name)#event->self
            return node_list
        else:
            #pdb.set_trace()
            event.witness = True
            first = self.check_supermajority(node_list, event, thresh_events)#added self#event.sp->self
            for i in first:
                if i not in node_list:
                    #pdb.set_trace()
                    second = self.check_supermajority(node_list, event, thresh_events)#self#event.op->self
                    print("First: {}\nSecond: {}\n".format(first, second))

        if(len(node_list) >	thresh_events):
            return True
        else:
            return False

    def print_event_data(self):
        '''
		Prints the data contained in the current Event.

		'''

        if self.op[0] != None:
            op_temp = self.op[0].name
        else:
            op_temp = None

        print("Data: {}\nTime: {}\nSP: {}\nOP: {}".format(self.data, self.timestamp, self.sp[0].name, op_temp))
        return


class Node:

    def __init__(self, name): 
            self.name = name
            self.signing_key = nacl.signing.SigningKey.generate()
            self.hg = {}# HG Struct: Dictionary containing lists pertaining to keys with names of Nodes
            self.sync_request = False	# Sync request flag for simulation
            self.sync_active = False
            self.network = None 	# Simulated network
            self.round = 1 #needed for divide_rounds
    def print_hashgraph(self):

        for i in self.network.nodes:
            print("Node: {}".format(i.name))
            print(self.hg[i.name])
            print("\n\n")

    def create_event(self, data=None, sync_node=None):
        '''
        Creates a single Event on the Hashgraph IAW the Swirlds Whitepaper. Appends the new Event to the current Node's Hashgraph.

        Args:
        	data (String): Contains sampled relay data.
        	sync_node (object Node): The target Node that is sending the new Hashgraph data.

        '''
        #pdb.set_trace()
        if (len(self.hg[self.name]) != 0):
			# If not the init Event, generate hashes for the self- and other-parent Events
            sp_hash = sign_event(self.hg[self.name][-1])
            op_hash = sign_event(sync_node.hg[sync_node.name][-1])
        else:
			# If init Event, no parent events Exist
            sp_hash = None
            op_hash = None

        timestamp = datetime.datetime.now()
        new_event = Event(timestamp, data, self, sync_node, sp_hash, op_hash, self.name)

        self.hg[self.name].append(new_event)

        return

    def generate_random_data(self):		# TODO: replace with relay sampling in the actual implementation
        '''
        Generates random data to simulate sampling a relay in the microgrid.

        Returns:
            (String): Contains the randomly-generated, simulated sample data.

        '''

        pseudo_data = "V1: " + str(random.random()) + "V2: " + str(random.random()) + "V3: " + str(random.random())
        return pseudo_data

    def sign_event(self, event):
        '''
        Uses Pickle to convert the event object to type byte. Signs the byte-type event created or agreed upon by the member and generates a verify key and a hex encoded verify key.

        Args:
            event (object Event): Event object to be signed by the member.

        Returns:
            (tuple): Contains the signed event, verify key, and the hex encoding of the key.

        '''

		# Convert event to type byte to begin encryption of full event and not the obj-type
        obj_string = pickle.dumps(event)

		# Hash the event obj string
        signed = self.signing_key.sign(obj_string)
        verify_key = self.signing_key.verify_key
        verify_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

        return (signed, verify_key, verify_hex)

    def verify_event(self, event, parent_targ):
        '''
        Verifies the key by checking the parent and the hex encoded verify key with the signed byte-type event.

        Args:
            event (class Event): The event to be verified.
            parent_targ (String): Which parent is being verified. Either "self" or other.

        Returns:
            (int): Value -1 for bad signature, 0 for successful verification.

        '''

        if parent_targ == "self":
            verify_key = nacl.signing.VerifyKey(event.sp_hash[2], encoder=nacl.encoding.HexEncoder)
            try:
                verify_key.verify(event.sp_hash[0])
            except nacl.exceptions.BadSignatureError:
                return -1
            return 0
        else:
            verify_key = nacl.signing.VerifyKey(event.op_hash[2], encoder=nacl.encoding.HexEncoder)
            try:
                verify_key.verify(event.op_hash[0])
            except nacl.exceptions.BadSignatureError:
                return -1
            return 0

        return

    def find_targ_idx(self, node):
        '''
		Returns the index of a given node name in the current node's hashgraph.

		Args:
			node (String): The name of the node whose index you wish to return

		Returns:
			(Int): Index of the target node in the current node's hashgraph.

        '''

        targ_idx = 0
        for i in self.network.nodes:
            if i.name == targ_node:
                break
            targ_idx += 1

        return targ_idx

    def begin_sync(self, targ_node):
        '''
        Begins syncing with another Node. Sends current HG to be copied by the receiving Node.

        Args:
            targ_node (String): The name of the Node being synced with.

        '''

        if SIM:

			# Simulate fetching data from relay (while allowing script to demonstrate algorithm execution by waiting)
            print("Syncing with node: {}... ".format(targ_node))
            time.sleep(2)
			
			# Send the receiving node a sync request and flag it
			# Also, fix this so you send flag data to another node in the actual implementation

			#searches through nodes to find one with matching name
            targ_idx = 0
            for i in self.network.nodes:
                if i.name == targ_node:
                    break
                targ_idx += 1
            self.network.nodes[targ_idx].sync_request = True

			# ACTUAL IMPLEMENTATION: Use sockets to send hg to receiver

			# Compare hg to receiver's hg and copy nodes that are valid and not known (Done in wait_sync in actual implementation)
			# dict 1 = self.hg
			# dict 2 = self.network.nodes[targ_idx].hg
            dol1 = self.hg
            dol2 = self.network.nodes[targ_idx].hg
            keys = set(dol1).union(dol2)
            no = []
            dol3 = dict((k, dol1.get(k, no) + dol2.get(k, no)) for k in keys)
            for i in dol3:
                dol3[i] = list(dict.fromkeys(dol3[i]))
            self.hg = dol3
            self.network.nodes[targ_idx].hg = dol3
            pdb.set_trace()
			# Create new event after comparing graphs to finish sync
            self.network.nodes[targ_idx].hg[targ_node].append(Event(time, data=self.generate_random_data(), self_parent=self.network.nodes[targ_idx].name, other_parent=self.name,self_parent_event_hash=None, other_parent_event_hash=None, node=None))#need to match up all the inputs
			
			# Wait for the receiving node to finish syncing on their end
            while self.network.nodes[targ_idx].sync_active:
                pass

        else:

			# TODO: Include non-simulator code here.
            pass

        return

    def wait_sync(self):
        '''
        Waits for another Node to begin syncing. Compares contents of both HG's and copies all new Events not in current HG.

        '''

        if SIM:

			# Wait for a sending node to initiate a sync request
            while not self.sync_request:
                pass

			#print("Node: {}, Connection Established from sender".format(self.name))

			# TODO: Compare hg to receiver's hg and copy nodes that are valid and not known
			# This will be done in the actual implementation

			#print("Comparing graphs...")
            time.sleep(2)
			
			#print("Sync complete")
			# Complete sync by unflagging
            self.sync_active = False

        else:

			# TODO: Include non-simulator code here.
            pass

        return

    def divide_rounds(self):
        '''
		print("Dividing rounds:")
		for i in network.nodes:
			i.network = nw
			for j in self.nodes:		#need to figure out why TODO: i.create_event does not produce sp_hash or possibly anything else.
				i.hg[j.name] = [] 	# Creates empty list for each node that will contain all events
			i.create_event()		# Create empty init Event for each Node
		'''
        pdb.set_trace()
        num_of_events = len(self.hg)
        thresh = num_of_events*2/3
        round = 0
        #unable to get rounds to increase and witnesses. i.sp[0].round > round throws an str error 
        for i in self.hg[self.name]:
            try:
                ###setting round to the highest parent of the event
                
                if(i.sp[0] is not None):
                    if(i.sp[0].round > round):
                        round = i.sp[0].round
                    else:
                        round =round
                elif(i.sp[0] is None):
                    round = 1
                else:
                    round = 1
                    
                if(i.op[0] is not None):
                    if(i.op[0].round > round):
                        round = i.op[0].round
                    else:
                        round =round
                elif(i.op[0] is None):
                    round = 1
                else:
                    round = 1
                
                ###End of setting round to highest parent of the event
                if (i.check_supermajority([], i,thresh)):
                    i.round = round+1
                    print(" moved")
                else:
                    i.round = round
                    print(" stayed")
					# Check if current event can "strongly see" a supermajority of witness events of the same round
					#if :
					#	pass
                if ((i.sp[0] is None) ):
                    i.witness = True
                elif(i.sp[0] is not None):
                    if(i.sp[0].round is not None):
                        if (i.round < i.sp[0].round):
                            i.witness = False
                        else:
                            i.witness = True
                    else:
                        i.witness = False
                else:
                    i.witness = True
            except AttributeError:#This should not occur, if it does that means check_supermajority failed
                print("\ncontinue")
                
                #event_supermajority = i.check_supermajority([], i)
        
        
        return

    def decide_fame(self):

        print("Deciding fame:")


        return

    def find_order(self):

        print("Finding order:")


        return

    def main(self):
		
        while True:
            """
			 TODO: 
			 Choose random node 	-- DONE
			 Sync   			 	-- DONE
			 Divide Rounds			-- IN PROGRESS
			 Decide Fame
			 Find Order 
			"""

            if not SIM:

				# IMPORTANT: The following code will only be used in the actual implementation, not the simulation.
                rand_node_idx = random.randrange(N)
                
                while(current_node == rand_node_idx):
                    rand_node_idx = random.randrange(N)
                   
				# Pick random node != current node 
				#while(current_node == (rand_node_idx := random.randrange(N))):		
					#rand_node_idx = random.randrange(N)
           		 		

                rand_node = self.hg[hg_nodes[rand_node_idx]]
                t1 = threading.Thread(target=self.begin_sync, args=(rand_node,))
                t2 = threading.Thread(target=self.wait_sync, args=())

				# Begin sync and wait sync
                t1.start()
                t2.start()

				# Wait for sync to complete
                t1.join()
                t2.join()

				#print("\n______________________\n\n______________________\n")


def test_nodes(nw):
	'''
    Tests the Nodes on the network by simulating the begin_sync and wait_sync methods.

    Args:
        nw (object Network): Simulated Network.

    '''

	while True:

		r_node = random.choice(list(nw.nodes[current_node].hg))
		new_node = random.choice(list(nw.nodes[current_node].hg))
		# Pick random node != current node. Only works with most current version of Python 3.

        	

		while(r_node == (new_node)):#while(r_node == (new_node := random.choice(list(nw.nodes[current_node].hg)))):
			new_node = random.choice(list(nw.nodes[current_node].hg))
           		

		print("\nNode initiating sync: {}: Begin sync to node {}\n".format(r_node, new_node))

		time.sleep(2)

		r_idx = 0
		n_idx = 0
		for i in nw.nodes:
			if i.name == r_node:
				break
			r_idx += 1
		for i in nw.nodes:
			if i.name == new_node:
				break
			n_idx += 1
            

		# Simulation threading
		t1 = threading.Thread(target=nw.nodes[r_idx].begin_sync, args=(new_node,))
		t2 = threading.Thread(target=nw.nodes[n_idx].wait_sync, args=())
		
		t1.start()
		t2.start()

		t1.join()
		t2.join()

		print("\nNew event created. HG updated.\n______________________\n\n")

		for i in nw.nodes:
			print("--------\nHashgraph for Node {}: ".format(i.name))
			i.print_hashgraph()
			print("--------")

		print("\n______________________\n")

		time.sleep(2)

		# DIVIDE ROUNDS - This will run individually on each node

		for i in nw.nodes:
			i.divide_rounds()
		# DECIDE FAME - This will run individually on each node
		for i in nw.nodes:
			i.decide_fame()
		

		# FIND ORDER - This will run individually on each node
		for i in nw.nodes:
			i.find_order()
	return

#pdb.set_trace()
def main(nodes):

	# Initialize network
	network = Network()
	network.init_nodes(hg_nodes)
	network.node_set_network(network)
	# Display nodes
	network.print_nodes()
    
	# TEST: Check each Node
	for i in network.nodes:
	 	# TEST: Check Event contents for init Events
	 	i.hg[i.name][0].print_event_data()
	 	print("")

	
	test_nodes(network)	

main(hg_nodes)