#!/usr/bin/env python
import os
import getpass
import time
import bcrypt
import configparser
from .crypto_handler import (
    generate_keypair, check_keypair, sign_message, verify_signature,
    get_public_key_pem, get_private_key_pem, 
    get_public_key_from_pem, get_private_key_from_pem
)


def prompt():
    """
    Prompts the user for input and returns the input as a string.
    """
    return str(input("Heimdell #> "))


def prompt_secret():
    """
    Prompts the user for password input (hidden) and returns it as a string.
    """
    return getpass.getpass("Heimdell #> ")


class Setup:
    def __init__(self):
        self.DEBUG = True
        self.STATUS = "CONFIG"
        self.config = configparser.ConfigParser()
        self.config_file = ".config.ini"
        # Removing cryptography-specific constants since they're handled in crypto_handler
    
    def load_config(self):
        """
        Loads the .config.ini file and reads configuration.
        If the file doesn't exist, sets status to NEW_SETUP.
        """
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
                if 'KEYS' in self.config and 'PRIVATE_KEY' in self.config['KEYS']:
                    self.STATUS = "SETUP_COMPLETE"
                else:
                    self.STATUS = "INCOMPLETE_SETUP"
            except Exception as e:
                print(f"Error reading config: {e}")
                self.STATUS = "CONFIG_ERROR"
        else:
            self.STATUS = "NEW_SETUP"
    
    def add_to_config(self, section, variable_to_save, value_to_save):
        """
        Adds a new variable to the .config.ini file in the specified section.
        
        Args:
            section: The configuration section
            variable_to_save: The name of the variable to save
            value_to_save: The value of the variable to save
            
        Returns:
            bool: True if the variable was added successfully
        """
        # Read the current config
        self.config.read(self.config_file)
        
        # Create the section if it doesn't exist
        if section not in self.config:
            self.config[section] = {}
        
        # Add or update the variable in the section
        self.config[section][variable_to_save] = value_to_save
        
        # Save the entire updated configuration to the file
        try:
            with open(self.config_file, 'w') as file:  # Use 'w' to overwrite the file
                self.config.write(file)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def remove_from_config(self, section, variable_to_remove):
        """
        Removes a variable from the .config.ini file in the specified section.
        
        Args:
            section: The configuration section
            variable_to_remove: The name of the variable to remove
            
        Returns:
            bool: True if the variable was removed successfully
        """
        # Read the current config
        self.config.read(self.config_file)
        
        # Check if section and variable exist
        if section in self.config and variable_to_remove in self.config[section]:
            # Remove the variable
            self.config[section].pop(variable_to_remove)
            
            # If section is now empty, remove it too
            if not self.config[section]:
                self.config.remove_section(section)
            
            # Save the entire updated configuration to the file
            try:
                with open(self.config_file, 'w') as file:
                    self.config.write(file)
                return True
            except Exception as e:
                print(f"Error saving configuration: {e}")
                return False
        else:
            print(f"Section '{section}' or variable '{variable_to_remove}' not found in config")
            return False
    
    def get_from_config(self, section, variable):
        """
        Gets a value from the config file.
        
        Args:
            section: The section to get the value from
            variable: The variable to get
            
        Returns:
            str: The value of the variable or None if not found
        """
        # Ensure we have the latest config
        self.config.read(self.config_file)
        
        if section in self.config and variable in self.config[section]:
            return self.config[section][variable]
        return None
        
    def save_private_key(self, private_key):
        """
        Saves the private key to the .config.ini file.

        Args:
            private_key: The private key to save

        Returns:
            bool: True if the private key was saved successfully
        """
        private_key_pem = get_private_key_pem(private_key)
        return self.add_to_config('KEYS', 'PRIVATE_KEY', private_key_pem)
    
    def save_public_key(self, public_key):
        """
        Saves the public key to the .config.ini file.

        Args:
            public_key: The public key to save

        Returns:
            bool: True if the public key was saved successfully
        """
        public_key_pem = get_public_key_pem(public_key)
        return self.add_to_config('KEYS', 'PUBLIC_KEY', public_key_pem)
    
    def load_keys(self):
        """
        Loads the keypair from the config file.
        
        Returns:
            tuple: (private_key, public_key) or (None, None) if keys not found
        """
        private_key_pem = self.get_from_config('KEYS', 'PRIVATE_KEY')
        public_key_pem = self.get_from_config('KEYS', 'PUBLIC_KEY')
        
        if not private_key_pem or not public_key_pem:
            return None, None
        
        try:
            private_key = get_private_key_from_pem(private_key_pem)
            public_key = get_public_key_from_pem(public_key_pem)
            
            # Verify the keypair is valid
            if not check_keypair(public_key, private_key):
                print("Warning: Stored keypair validation failed!")
                return None, None
                
            return private_key, public_key
        except Exception as e:
            print(f"Error loading keys: {e}")
            return None, None
    
    def setup_prompt(self):
        """
        Interactive setup process for Heimdell agent.
        Collects necessary configuration and generates keypair.
        """
        print("""
        ==============================================================================================
                    _               _      _ _ 
          /\  /\___(_)_ __ ___   __| | ___| | |
         / /_/ / _ \ | '_ ` _ \ / _` |/ _ \ | |
        / __  /  __/ | | | | | | (_| |  __/ | |
        \/ /_/ \___|_|_| |_| |_|\__,_|\___|_|_|
        ==============================================================================================
                                            Heimdell Agent Setup
                                            --Built by CyberNash Technologies--
                                            --SadNinja--

        """)
        print("Please provide the manager URL for the agent to send data to:")
        agent_manager = prompt()
        
        print("Please provide Heimdell agent admin password:")
        agent_password = prompt_secret()
        hashed_password = bcrypt.hashpw(agent_password.encode(), bcrypt.gensalt())
        
        print("Generating keypair...")
        time.sleep(1)  # Shortened for better UX
        private_key, public_key = generate_keypair()
        print("Keypair generated.")
        
        # Test the keypair
        test_message = "Heimdell test message"
        test_signature = sign_message(private_key, test_message)
        if verify_signature(public_key, test_message, test_signature):
            print("Keypair verification successful.")
        else:
            print("ERROR: Keypair verification failed! Aborting setup.")
            return False
        
        print("Saving keypair...")
        self.save_private_key(private_key)
        self.save_public_key(public_key)
        
        print("Please provide identifier name for the agent:")
        agent_name = prompt()
        
        print("Please provide identifier description for the agent:")
        agent_desc = prompt()

        print("Communicating with Athena...")
        time.sleep(3)
        
        print("Saving agent configuration...")
        self.add_to_config('AGENT', 'MANAGER', agent_manager)
        self.add_to_config('AGENT', 'NAME', agent_name)
        self.add_to_config('AGENT', 'DESCRIPTION', agent_desc)
        self.add_to_config('SECURITY', 'PASSWORD_HASH', hashed_password.decode())
        
        print("Configuration saved successfully.")
        self.STATUS = "SETUP_COMPLETE"
        return True


def load_keys():
    """
    Helper function to load keys through the Setup class.
    
    Returns:
        tuple: (private_key, public_key) or (None, None) if keys not found
    """
    setup = Setup()
    return setup.load_keys()


if __name__ == "__main__":
    setup = Setup()
    setup.load_config()
    
    if setup.STATUS == "NEW_SETUP" or setup.STATUS == "INCOMPLETE_SETUP":
        setup.setup_prompt()
    elif setup.STATUS == "SETUP_COMPLETE":
        # Test loading keys to verify everything is working
        private_key, public_key = setup.load_keys()
        if private_key and public_key:
            print("Heimdell agent is configured and keys loaded successfully.")
            agent_name = setup.get_from_config('AGENT', 'NAME')
            agent_manager = setup.get_from_config('AGENT', 'MANAGER')
            print(f"Agent '{agent_name}' is configured to connect to: {agent_manager}")
        else:
            print("Heimdell agent configuration error: Unable to load keys.")
    else:
        print(f"Heimdell agent has configuration issues. Status: {setup.STATUS}")