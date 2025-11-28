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
import sys
import csv
import json
import time
import requests
from utils import load_config, iso8601_to_timestamp, is_timeover, get_user_team
from github import Github, decode_content, get_github_path
from io import StringIO
from string import Template

def compute_score(score, attacker, points):
    if attacker in score:
        score[attacker] += points
    else:
        score[attacker] = points

def compute_unintended(start, end, freq, unintended_pts):
    return int(end - start) / int(freq) * int(unintended_pts)

def update_deferred(score, unint_attack_hist, freq, unintended_pts, end_time):
    curr_time = time.time()
    end_time = iso8601_to_timestamp(end_time)
    end_time = min(curr_time, end_time)
    for attack_id, start_time in unint_attack_hist.items():
        attacker = attack_id.split('_')[0]
        pts = compute_unintended(start_time, end_time, freq, unintended_pts)
        compute_score(score, attacker, pts)

def display_score(data, freq, unintended_pts, end_time, config, github, pin_time = None):
    f = StringIO(data)
    reader = csv.reader(f, delimiter=',')
    score = {}
    for row in reader:
        if not row or len(row) < 6:
            continue
        t = float(row[0])
        if pin_time is not None and t >= float(pin_time):
            break
        attacker, points = row[1], int(row[5])
        attacker, points = row[1], int(row[5])
        
        # Resolve team
        team = get_user_team(attacker, config, github)
        if team:
            compute_score(score, team, points)
        else:
            # If no team found (e.g. admin or unmapped), maybe skip or show as user?
            # User requested team scores. Let's skip if not in a team (like admin).
            pass

    if pin_time is None:
        for team, points in sorted(score.items(), key=lambda item: item[1], reverse=True):
            print('%-20s: %d' % (team, points))
    else:
        return score

def show_score(token, config_file):
    config = load_config(config_file)
    scoreboard_url = config['score_board']
    freq = float(config['round_frequency'])
    unintended_pts = float(config['unintended_pts'])
    end_time = config['end_time']
    start_time = config['start_time']
    path = get_github_path(scoreboard_url)
    # Try to fetch raw file first to avoid API rate limits
    # https://raw.githubusercontent.com/{owner}/{repo}/main/score.csv
    
    raw_base = f"https://raw.githubusercontent.com/{path}"
    csv_content = None
    
    # Try main branch
    try:
        r = requests.get(f"{raw_base}/main/score.csv")
        if r.status_code == 200:
            csv_content = r.text
    except:
        pass
        
    # Try master branch if main failed
    if csv_content is None:
        try:
            r = requests.get(f"{raw_base}/master/score.csv")
            if r.status_code == 200:
                csv_content = r.text
        except:
            pass
            
    # Fallback to API if raw fetch failed (e.g. private repo with token)
    username = config.get('player', '') if token else ''
    g = Github(username, token)
    if csv_content is None:
        print("[*] Raw fetch failed. Falling back to API...")
        if g.get('/repos/' + path) is None:
            print('[*] Failed to access the repository %s' % path)
            sys.exit()
        r = g.get('/repos/' + path + '/contents/' + 'score.csv')
        if r is None:
            print('[*] Failed to get the score file.')
            sys.exit()
        csv_content = decode_content(r)
        if isinstance(csv_content, bytes):
            csv_content = csv_content.decode('utf-8')
            
    display_score(csv_content, freq, unintended_pts, end_time, config, g)

    hour_from_start = 0
    log = {}

    graph_start_time = int(iso8601_to_timestamp(start_time))
    if is_timeover(config):
        graph_end_time = int(iso8601_to_timestamp(end_time))
    else:
        graph_end_time = int(time.time())

    for i in range(graph_start_time, graph_end_time, 3600):
        log[hour_from_start] = display_score(csv_content, freq, unintended_pts, end_time, config, g, i)
        hour_from_start = hour_from_start+1
