#!/bin/bash
# Define ANSI color escape codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Define variables for the jump hosts
SSH_USER="user"  # Replace with your username
SSH_KEY="/path/to/your/ssh/key"  # Replace with the path to your SSH private key file

# Define the jump hosts manually in the desired order
JUMP_HOST_1="hostname1"
JUMP_HOST_2="hostname2"
JUMP_HOST_3="hostname3"
# Add more jump hosts as needed

# Define the final destination host and port
DEST_HOST="final-destination-hostname"
DEST_PORT="22"  # Replace with the SSH port on the final destination host

# Function to check for internet connectivity
check_internet() {
  if ping -c 1 google.com > /dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

# Function to establish the SSH tunnel through manually defined jump hosts
establish_tunnel() {
  # Use the -J option to specify the manually defined jump hosts
  if ssh -i "$SSH_KEY" -N -L 2222:localhost:2222 -J "$JUMP_HOST_1,$JUMP_HOST_2,$JUMP_HOST_3"; then
    return 0
  else
    return 1
  fi
}

# Function to print colored messages
print_message() {
  local color="$1"
  local message="$2"
  echo -e "${color}${message}${NC}"
}

# Main loop
while true; do
  if check_internet; then
    print_message "${GREEN}" "Internet is up."
    if ! pgrep -f "ssh.*-L 2222:localhost:2222" > /dev/null; then
      print_message "${RED}" "SSH tunnel not running. Establishing tunnel..."
      if establish_tunnel; then
        print_message "${GREEN}" "SSH tunnel established successfully."
      else
        print_message "${RED}" "Failed to establish SSH tunnel."
      fi
      sleep 5
    else
      print_message "${GREEN}" "SSH tunnel is already running."
    fi
  else
    print_message "${RED}" "No internet access. Waiting..."
  fi
  sleep 60  # Check every 60 seconds
done