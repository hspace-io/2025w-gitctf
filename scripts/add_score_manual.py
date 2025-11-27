#!/usr/bin/env python
###############################################################################
# Git-based CTF - Manual Score Adder
###############################################################################
# This script helps manually add scores to the scoreboard for testing purposes
#
# Usage: python3 add_score_manual.py [scoreboard_repo_path] [timestamp] [attacker] [defender] [branch] [kind] [points]
# Example: python3 add_score_manual.py ./test-scoreboard 1700000000.0 team1 team2 bug1 intended 50

import sys
import os
import time
import subprocess

def add_score(scoreboard_dir, timestamp, attacker, defender, branch, kind, points):
    """Add a score entry to score.csv and commit/push"""
    
    score_file = os.path.join(scoreboard_dir, 'score.csv')
    
    # Check if scoreboard directory exists
    if not os.path.isdir(scoreboard_dir):
        print(f"[*] Error: Scoreboard directory '{scoreboard_dir}' does not exist")
        print(f"[*] Please clone the scoreboard repository first:")
        print(f"    git clone https://github.com/[owner]/[repo-name] {scoreboard_dir}")
        return False
    
    # Read existing score.csv if it exists
    lines = []
    if os.path.isfile(score_file):
        with open(score_file, 'r') as f:
            lines = f.readlines()
    
    # Append new score entry
    new_entry = f"{timestamp},{attacker},{defender},{branch},{kind},{points}\n"
    lines.append(new_entry)
    
    # Write back to file
    with open(score_file, 'w') as f:
        f.writelines(lines)
    
    print(f"[*] Added score entry: {new_entry.strip()}")
    
    # Git add, commit, and push
    try:
        subprocess.run(['git', 'add', 'score.csv'], cwd=scoreboard_dir, check=True)
        commit_msg = f"Add score: {attacker} +{points} ({branch}, {kind})"
        subprocess.run(['git', 'commit', '-m', commit_msg], cwd=scoreboard_dir, check=True)
        subprocess.run(['git', 'push', 'origin', 'main'], cwd=scoreboard_dir, check=True)
        print(f"[*] Successfully committed and pushed to scoreboard")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[*] Error during git operations: {e}")
        print(f"[*] You may need to manually commit and push:")
        print(f"    cd {scoreboard_dir}")
        print(f"    git add score.csv")
        print(f"    git commit -m 'Add score entry'")
        print(f"    git push origin main")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Usage: python3 add_score_manual.py [scoreboard_dir] [timestamp] [attacker] [defender] [branch] [kind] [points]")
        print()
        print("Arguments:")
        print("  scoreboard_dir: Path to cloned scoreboard repository")
        print("  timestamp:      Unix timestamp (float, e.g., 1700000000.0)")
        print("  attacker:       Attacker team/player name")
        print("  defender:       Defender team/player name")
        print("  branch:         Branch name (e.g., bug1, bug2)")
        print("  kind:           Bug kind (intended or unintended)")
        print("  points:         Points earned (integer)")
        print()
        print("Example:")
        print("  python3 add_score_manual.py ./test-scoreboard 1700000000.0 team1 team2 bug1 intended 50")
        print()
        print("To use current timestamp:")
        print("  python3 add_score_manual.py ./test-scoreboard $(date +%s) team1 team2 bug1 intended 50")
        sys.exit(1)
    
    scoreboard_dir = sys.argv[1]
    timestamp = sys.argv[2]
    attacker = sys.argv[3]
    defender = sys.argv[4]
    branch = sys.argv[5]
    kind = sys.argv[6]
    points = int(sys.argv[7])
    
    if kind not in ['intended', 'unintended']:
        print("[*] Error: kind must be 'intended' or 'unintended'")
        sys.exit(1)
    
    success = add_score(scoreboard_dir, timestamp, attacker, defender, branch, kind, points)
    sys.exit(0 if success else 1)

