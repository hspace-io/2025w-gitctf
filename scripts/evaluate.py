#!/usr/bin/env python
###############################################################################
# Git-based CTF
###############################################################################
#
# Author: SeongIl Wi <seongil.wi@kaist.ac.kr>
#         Jaeseung Choi <jschoi17@kaist.ac.kr>
#         Sang Kil Cha <sangkilc@kaist.ac.kr>
#
# Copyright (c) 2018 SoftSec Lab. KAIST
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import re
import sys
import csv
import importlib
import json
import time
import calendar
from issue import is_closed, create_comment, close_issue
from issue import create_label, update_label, get_github_issue
from cmd import run_command
from utils import load_config, rmdir, rmfile, iso8601_to_timestamp, is_timeover, get_user_team
from github import Github, get_github_path
from git import clone, checkout, get_next_commit_hash
from verify_issue import verify_issue

msg_file = 'msg' # Temporarily store commit message

def failure_action(repo_owner, repo_name, issue_no, comment, id, github):
    create_label(repo_owner, repo_name, "failed", "000000", \
            "Verification failed.", github)
    update_label(repo_owner, repo_name, issue_no, github, "failed")
    create_comment(repo_owner, repo_name, issue_no, comment, github)
    close_issue(repo_owner, repo_name, issue_no, github)
    mark_as_read(id, github)

def get_target_repos(config):
    repos = []
    for team in config['teams']:
        repos.append(config['teams'][team]['repo_name'])
    return repos

def is_issue(noti):
    return noti['subject']['type'] == 'Issue'

def is_target(noti, target_repos):
    return noti['repository']['name'] in target_repos

def get_issue_number(noti):
    return int(noti['subject']['url'].split('/')[-1])

def get_issue_id(noti):
    return noti['url'].split('/')[-1]

def get_issue_gen_time(noti):
    return iso8601_to_timestamp(noti['updated_at'])



def get_issues_new(config, target_repos, github):
    issues = []
    interval = 10 # Poll more frequently or keep 60? 60 is safe.
    
    owner = config['repo_owner']
    
    for repo_name in target_repos:
        query = '/repos/%s/%s/issues?state=open&labels=bug' % (owner, repo_name)
        # We can filter by label if we want, but let's just get all open issues and filter manually
        # to match the original logic which filtered by "is_issue".
        # Actually, let's just get all open issues.
        query = '/repos/%s/%s/issues?state=open' % (owner, repo_name)
        
        try:
            repo_issues = github.get(query)
            if repo_issues is None:
                continue
        except Exception as e:
            print(f"[*] Failed to fetch issues for {repo_name}: {e}")
            continue
            
        for issue in repo_issues:
            # Ignore submissions from the repo owner (admin/maintainer) and specific admins
            ignored_users = [owner, 'hy30nq', 'Ark3a', 'br0nzu']
            if issue['user']['login'] in ignored_users:
                print(f"[*] Skipping submission from admin: {issue['user']['login']}")
                continue

            # Check if already processed
            labels = [l['name'] for l in issue.get('labels', [])]
            if 'eval' in labels or 'verified' in labels or 'failed' in labels or 'defended' in labels:
                continue
                
            # It's a new candidate
            num = issue['number']
            id = None # No notification ID
            gen_time = iso8601_to_timestamp(issue['updated_at'])
            issues.append((repo_name, num, id, gen_time))
            
    return issues, interval

def mark_as_read(issue_id, github):
    if issue_id is None:
        return
    query = '/notifications/threads/' + issue_id
    return github.patch(query, None)

def get_defender(config, target_repo):
    teams = config['teams']
    defender = None
    for team in teams:
        if teams[team]['repo_name'] == target_repo:
            defender = team
            break
    return defender



def sync_scoreboard(scoreboard_dir):
    run_command('git reset --hard', scoreboard_dir)
    run_command('git pull', scoreboard_dir)

def write_score(stamp, info, scoreboard_dir, pts):
    with open(os.path.join(scoreboard_dir, 'score.csv'), 'a') as f:
        attacker = info['attacker']
        defender = info['defender']
        branch = info['branch']
        kind = info['bugkind']
        f.write('%s,%s,%s,%s,%s,%d\n' % (stamp, attacker, defender, branch, \
                kind, pts))

def write_message(info, scoreboard_dir, pts):
    with open(os.path.join(scoreboard_dir, msg_file), 'w') as f:
        attacker = info['attacker']
        defender = info['defender']
        branch = info['branch']
        kind = info['bugkind']
        f.write('[Score] %s +%d\n\n' % (attacker, pts))
        if pts == 0: # Protocol to indicate successfull defense
            f.write('%s defended `%s` %s with %s' % (defender, branch, attacker, kind))
        else:
            f.write('%s attacked `%s` %s of %s' % (attacker, branch, kind, defender))

def commit_and_push(scoreboard_dir):
    _, _, r = run_command('git add score.csv', scoreboard_dir)
    if r != 0:
        print('[*] Failed to git add score.csv.')
        return False
    _, _, r = run_command('git commit -F %s' % msg_file, scoreboard_dir)
    if r != 0:
        print('[*] Failed to commit score.csv.')
        return False
    _, _, r = run_command('git push origin HEAD', scoreboard_dir)
    if r != 0:
        print('[*] Failed to push the score.')
        return False
    rmfile(os.path.join(scoreboard_dir, msg_file))
    return True

def find_the_last_attack(scoreboard_dir, timestamp, info, config, github):
    last_commit = None
    scoreboard_path = os.path.join(scoreboard_dir, 'score.csv')
    
    # Resolve attacker team dynamically
    attacker_team = get_user_team(info['attacker'], config, github)
    
    if os.path.isfile(scoreboard_path):
        with open(scoreboard_path) as f:
            reader = csv.reader(f, delimiter=',')
            for row in reader:
                try:
                    row_timestamp = int(float(row[0]))
                except ValueError:
                    continue
                    
                if len(row[4]) == 40:
                    # Check if the attack is against the same defender and branch
                    if row[2] == info['defender'] and row[3] == info['branch']:
                        # Check if the attacker is from the same team
                        row_attacker = row[1]
                        # row_attacker should already be a team name if recorded correctly,
                        # but let's use get_user_team to be safe/consistent.
                        row_attacker_team = get_user_team(row_attacker, config, github)
                        
                        # If teams match (and are not None), it's a duplicate attack from the same team
                        if attacker_team and row_attacker_team and attacker_team == row_attacker_team:
                            last_commit = row[4]
                        # Fallback: if team info is missing, check username equality (legacy behavior)
                        elif row_attacker == info['attacker']:
                            last_commit = row[4]
    return last_commit

def get_next_commit(last_commit, defender, branch, config):
    repo_name = config['teams'][defender]['repo_name']
    rmdir(repo_name)
    clone(config['repo_owner'], repo_name)
    next_commit_hash = get_next_commit_hash(repo_name, branch, last_commit)
    rmdir(repo_name)
    print (next_commit_hash)
    if next_commit_hash == '':
        return None
    else:
        return next_commit_hash

# XXX: Calling verify_issue() multiple times involves redundant process
# internally. We may consider replacing this by calling fetch() once and then
# calling verify_exploit() multiple times.
def process_unintended(repo_name, num, config, gen_time, info, scoreboard, id,
                        github, repo_owner):
    unintended_pts = config['unintended_pts']
    
    # Resolve attacker to team name for scoreboard
    attacker_team = get_user_team(info['attacker'], config, github)
    if attacker_team:
        print(f"[*] Mapping attacker {info['attacker']} to team {attacker_team}")
        info['attacker'] = attacker_team
    else:
        print(f"[*] Warning: Could not map attacker {info['attacker']} to a team.")
        
    target_commit = find_the_last_attack(scoreboard, gen_time, info, config, github)

    if target_commit is None:
        # This exploit is previously unseen, give point.
        write_score(gen_time, info, scoreboard, unintended_pts)
        write_message(info, scoreboard, unintended_pts)
        commit_and_push(scoreboard)
    else:
        while True:
            target_commit = get_next_commit(target_commit, \
                    info['defender'], info['branch'], config)
            if target_commit is None:
                print ('[*] No more commit to verify against')
                break

            _, verified_commit, _, _ = \
                verify_issue(info['defender'], repo_name, num, config, \
                github, target_commit)
            info['bugkind'] = target_commit
            if verified_commit is None:
                # Found a correct patch that defeats the exploit.
                current_time = int(time.time())
                write_score(current_time, info, scoreboard, 0)
                write_message(info, scoreboard, 0)
                commit_and_push(scoreboard)
                mark_as_read(id, github)
                create_label(repo_owner, repo_name, "defended", "0000ff", \
                        "Defended.", github)
                update_label(repo_owner, repo_name, num, github, "defended")
                break
            else:
                # Exploit still works on this commit, update score and continue
                write_score(gen_time, info, scoreboard, unintended_pts)
                write_message(info, scoreboard, unintended_pts)
                commit_and_push(scoreboard)

def process_issue(repo_name, num, id, config, gen_time, github, scoreboard):
    repo_owner = config['repo_owner']
    if is_closed(repo_owner, repo_name, num, github):
        mark_as_read(id, github)
        return


    title, _, _, _ = get_github_issue(repo_owner, repo_name, num, github)

    create_label(repo_owner, repo_name, "eval", "DA0019", \
            "Exploit is under review.", github)
    update_label(repo_owner, repo_name, num, github, "eval")

    defender = get_defender(config, repo_name)
    if defender is None:
        print ('[*] Fatal error: unknown target %s.' % repo_name)
        sys.exit()
        return

    branch, commit, attacker, log = verify_issue(defender, repo_name, num, \
            config, github)
    if branch is None:
        log = "```\n" + log + "```"
        failure_action(repo_owner, repo_name, num, \
                log + '\n\n[*] The exploit did not work.', id, github)
        return

        return
    
    attacker_team = get_user_team(attacker, config, github)
    if attacker_team is None:
        failure_action(repo_owner, repo_name, num, \
                '[*] User %s is not recognized (not in config and not a collaborator).' % attacker, \
                id, github)
        return

    if attacker_team == defender:
        failure_action(repo_owner, repo_name, num, \
                '[*] Self-attack is not allowed: %s.' % attacker, \
                id, github)
        return

    create_label(repo_owner, repo_name, "verified", "9466CB", \
            "Successfully verified.", github)
    update_label(repo_owner, repo_name, num, github, "verified")

    kind = commit
    info = {'attacker': attacker, 'defender': defender,
            'branch': branch, 'bugkind': kind}
    sync_scoreboard(scoreboard)
    process_unintended(repo_name, num, config, gen_time, info, scoreboard,
            id, github, repo_owner)

def prepare_scoreboard_repo(url, token):
    path = get_github_path(url).split('/')
    scoreboard_owner = path[0]
    scoreboard_name = path[1]
    scoreboard_dir = '.score'
    clone(scoreboard_owner, scoreboard_name, False, scoreboard_dir)
    
    # Configure remote with token for push access
    if token:
        auth_url = f"https://{token}@github.com/{scoreboard_owner}/{scoreboard_name}.git"
        run_command(f"git remote set-url origin {auth_url}", scoreboard_dir)
        
    return scoreboard_dir

def start_eval(config, github):
    target_repos = get_target_repos(config)
    # We need to pass the token to prepare_scoreboard_repo. 
    # github object has the token in session headers but it's cleaner if passed or extracted.
    # github.session.headers['Authorization'] is 'token ...'
    token = None
    auth_header = github.session.headers.get('Authorization')
    if auth_header and auth_header.startswith('token '):
        token = auth_header.split(' ')[1]
        
    scoreboard = prepare_scoreboard_repo(config['score_board'], token)
    finalize = False
    while (not finalize):
        if (is_timeover(config)):
            finalize = True
        issues, interval = get_issues_new(config, target_repos, github)
        if not issues:
            print('[*] No news. Sleep for %d seconds.' % interval)
            time.sleep(interval)
            continue
        print('[*] %d new issues.' % len(issues))
        for repo, num, id, gen_time in issues:
            process_issue(repo, num, id, config, gen_time, github, scoreboard)
    print ('[*] Time is over!')
    return

def evaluate(config_file, token):
    config = load_config(config_file)
    github = Github(config['player'], token)
    return start_eval(config, github)

