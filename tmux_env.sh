#!/bin/bash

SESSION="SMC Cyber"
SESSIONEXISTS=$(tmux list-sessions | grep $SESSION)

# Only create tmux session if it doesn't already exist
if [ "$SESSIONEXISTS" = "" ]
then
  tmux new-session -d -s $SESSION
  
  # Setup build environment
  tmux rename-window -t 0 'run'
  tmux send-keys -t 'run' 'source venv/bin/activate' C-m

  # Setup coding environment
  tmux new-window -t $SESSION:1 -n 'code'
  tmux send-keys -t 'code' 'ls' C-m
  tmux split-window -h
  tmux send-keys -t 'code' 'ls' C-m
fi 

# Attach Session, on the Main window
tmux attach-session -t $SESSION:1
