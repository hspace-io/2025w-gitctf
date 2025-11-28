#!/usr/bin/env python3
import sys
import os
import csv
from github import Github
from utils import load_config, base_dir, run_command, rmfile

def reset_labels(config, github):
    print("[*] Resetting issue labels...")
    owner = config['repo_owner']
    target_labels = ['eval', 'verified', 'failed', 'defended']
    
    for team_name, team_info in config['teams'].items():
        repo_name = team_info['repo_name']
        print(f"[*] Processing repo: {repo_name}")
        
        # Fetch all issues (open and closed) to be thorough, or just open?
        # Let's do open for now as closed ones are likely done.
        # Actually, if we want to re-eval, we might need to check closed ones too if they were closed by the script?
        # The script doesn't close issues usually, just labels them.
        query = f'/repos/{owner}/{repo_name}/issues?state=open'
        issues = github.get(query)
        
        if not issues:
            continue
            
        for issue in issues:
            number = issue['number']
            labels = [l['name'] for l in issue.get('labels', [])]
            
            for label in labels:
                if label in target_labels:
                    print(f"    [-] Removing label '{label}' from issue #{number}")
                    # DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}
                    delete_url = f"https://api.github.com/repos/{owner}/{repo_name}/issues/{number}/labels/{label}"
                    # github.session is a requests.Session object
                    res = github.session.delete(delete_url)
                    if res.status_code != 204 and res.status_code != 200:
                        print(f"    [!] Failed to delete label: {res.status_code} {res.text}")

def reset_scoreboard(config, github):
    print("[*] Resetting scoreboard...")
    # Clone scoreboard
    # We need to use the token for push
    token = None
    auth_header = github.session.headers.get('Authorization')
    if auth_header and auth_header.startswith('token '):
        token = auth_header.split(' ')[1]
        
    from evaluate import prepare_scoreboard_repo
    scoreboard_dir = prepare_scoreboard_repo(config['score_board'], token)
    
    # Clear score.csv
    score_path = os.path.join(scoreboard_dir, 'score.csv')
    with open(score_path, 'w') as f:
        f.write('') # Empty file
        
    # Commit and push
    run_command('git add score.csv', scoreboard_dir)
    run_command('git commit -m "[Reset] Scoreboard reset"', scoreboard_dir)
    _, _, r = run_command('git push origin HEAD', scoreboard_dir)
    
    if r == 0:
        print("[*] Scoreboard reset successfully.")
    else:
        print("[*] Failed to push reset scoreboard.")

def main():
    if len(sys.argv) < 5:
        print("Usage: python3 reset_ctf.py --conf <config_file> --token <github_token>")
        sys.exit(1)
        
    config_file = sys.argv[2]
    token = sys.argv[4]
    
    config = load_config(config_file)
    github = Github(config['player'], token)
    
    reset_labels(config, github)
    reset_scoreboard(config, github)
    print("[*] CTF Reset Complete.")

if __name__ == '__main__':
    main()
