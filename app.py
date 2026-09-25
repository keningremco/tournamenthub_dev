from flask import Flask, render_template, session, request, redirect, url_for, abort, jsonify, flash
from functools import wraps
import secrets
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import json
from flask_mail import Mail, Message
import re
import os
from dotenv import load_dotenv
from db.connection import get_db_connection
from auth.decorators import login_required
from permissions.permission import can_user
from services.lobbies import get_lobby_rounds_points, calc_prediction_points_game, get_lobby_leaderboard

load_dotenv()

app = Flask(__name__)
from api import api
app.register_blueprint(api)


app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config["MAIL_USERNAME"] = os.environ["MAIL_USERNAME"]
app.config["MAIL_PASSWORD"] = os.environ["MAIL_PASSWORD"]
app.config["MAIL_DEFAULT_SENDER"] = os.environ["MAIL_USERNAME"]


mail = Mail(app)

@app.route("/")
def home():
    userid = session.get('userid')
    return render_template('index.html', userid=userid)

@app.route("/login", methods=['POST', "GET"])
def login():
    logout()
    error = ""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        db, cursor = get_db_connection()
        try:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

            if not user:
                return render_template('login.html', error="username or password incorrect")

            if user and check_password_hash(user["password_hash"], password):
                session["userid"] = user["id"]
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error="username or password incorrect")
        finally:
            cursor.close()
            db.close()
    return render_template('login.html', error=error)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    userid = session.get('userid')
    if request.method == "POST":
        db, cursor = get_db_connection()
        email = request.form.get('email')
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if not user:
                return render_template('forgot_password.html', userid=userid, error="user not found")
            userid = user['id']
            cursor.execute('SELECT * FROM email_verification_tokens WHERE userId = %s', (userid,))
            email_verification_token = cursor.fetchone()
            if email_verification_token:
                token = email_verification_token['token']
            else:
                token = makeToken()
                cursor.execute('INSERT INTO email_verification_tokens (userId, token) VALUES (%s, %s)', (userid, token))
                db.commit()
            reset_link = url_for( "reset_password", token=token, _external=True )

            msg = Message( subject="Reset your TournamentHub password", recipients=[email] ) 

            msg.body = f"""
Hello, 

We received a request to reset the password for your TournamentHub account. 
You can reset your password by clicking the link below: 

{reset_link} 

If you did not request a password reset, you can safely ignore this email. 

This link can only be used to reset your password. 
TournamentHub """ 
            try: 
                mail.send(msg) 
                return "token send to your email"
            except Exception as e: 
                return 0
            
        finally:
            cursor.close()
            db.close()
        
    return render_template('forgot_password.html', userid=userid)

@app.route('/resetpassword/<token>', methods=["POST", "GET"])
def reset_password(token):
    if request.method == "POST":
        
        try:
            db, cursor = get_db_connection()
            cursor.execute("SELECT * FROM email_verification_tokens WHERE token = %s", (token,))
            email_verification_token = cursor.fetchone()
            if not email_verification_token:
                abort(404)
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            if not password or not confirm_password:
                return render_template('resetpassword', error='no passwords enterd or passwords not matching')
            if password != confirm_password:
                abort(404)
            userid = email_verification_token['userId']
            password_hash = generate_password_hash(password)
            cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (password_hash, userid))
            db.commit()
            cursor.execute('DELETE FROM email_verification_tokens WHERE token = %s', (token,))
            db.commit()
            return redirect(url_for('login'))
        finally:
            cursor.close()
            db.close()
    return render_template('resetpassword.html')

def makePrediction(userid, gameId, cursor):
    cursor.execute("""
                INSERT INTO predictions (userId, gameId) VALUES (%s, %s)
    """, (userid, gameId) )
    if cursor.rowcount != 1:
        abort(500)
    return True

def convert_to_json_string(data):
    return data.replace("'", '"')

@app.route("/saveprediction/<lobbyCode>", methods=["POST"])
@login_required
def savePrediction(lobbyCode):
    userid = session.get('userid')
    team1Score = request.form.get('team1_score')
    
    
    teamIds = json.loads(convert_to_json_string(request.form.get('game_ids')))
    if not teamIds:
        abort(404)
    team2Score = request.form.get('team2_score')
    gameId = request.form.get('game_id')
    db,cursor  =get_db_connection()
    if (team1Score or team2Score) == None:
        abort(404)
    try:
        cursor.execute("SELECT id FROM predictions WHERE gameId= %s AND userId = %s", (gameId, userid))
        prediction = cursor.fetchone()
        if not prediction:
            makePrediction(userid, gameId, cursor)
            db.commit()
        cursor.execute("SELECT id FROM predictions WHERE gameId= %s AND userId = %s", (gameId, userid))
        prediction = cursor.fetchone()
        predictionId = prediction['id']
        cursor.execute("SELECT * FROM predicted_scores WHERE predictionId = %s", (predictionId,))
        scores = cursor.fetchall()
        if not scores:
            teamId = teamIds['team1Id']
            cursor.execute("""
                INSERT INTO predicted_scores (predictionId, teamId) VALUES (%s, %s)
        """, (predictionId, teamId))
            db.commit()

            teamId = teamIds['team2Id']
            cursor.execute("""
                INSERT INTO predicted_scores (predictionId, teamId) VALUES (%s, %s)
        """, (predictionId, teamId))
            db.commit()

        cursor.execute("""
            UPDATE predicted_scores
            SET score = CASE
                WHEN teamId = %s THEN %s
                WHEN teamId = %s THEN %s
            END
            WHERE predictionId = %s
            AND teamId IN (%s, %s)
        """, (
            teamIds['team1Id'], team1Score,
            teamIds['team2Id'], team2Score,
            predictionId,
            teamIds['team1Id'], teamIds['team2Id']
        ))

        db.commit()

        return redirect(url_for('lobby', code=lobbyCode) + "#" + gameId)

        
    finally:
        cursor.close()
        db.close()

@app.route("/logout")
def logout():
    session.clear()
    return(redirect(url_for('home')))

@app.route('/tf/<tag>')
@login_required
def togglefeatured(tag):
    userid = session.get('userid')
    if not can_user(userid, 'site.manage_tags', site=True):
        flash("Je hebt geen toestemming om een tag featured te maken.", "error")
        return redirect(request.referrer or abort(403))
    print('hoi')
    db, cursor = get_db_connection()
    try:
        
        
        cursor.execute("""
            SELECT id
            FROM tags
            WHERE name = %s  """, (tag,))
        
        tagExist = cursor.fetchone()

        if not tagExist:
            cursor.execute("""
                INSERT INTO tags (name) VALUES (%s)
        """, (tag,))
            db.commit()
            tagId = cursor.lastrowid
        else:
            tagId = tagExist['id']
        
        cursor.execute("SELECT id FROM featured_tags WHERE tagId = %s", (tagId,))
        isFeatured = cursor.fetchone()

        if isFeatured:
            cursor.execute("DELETE FROM featured_tags WHERE tagId = %s", (tagId,))
            db.commit()
        else:
            cursor.execute("INSERT INTO featured_tags (tagId) VALUES (%s)", (tagId,))
            db.commit()
        return redirect(url_for('tournaments'))
    finally:
        cursor.close()
        db.close()


def makeToken():
    db, cursor = get_db_connection()

    try:
        while True:
            token = secrets.token_urlsafe(64)

            cursor.execute(
                """
                SELECT id
                FROM email_verification_tokens
                WHERE token = %s
                """,
                (token,)
            )

            if not cursor.fetchone():
                return token

    finally:
        cursor.close()
        db.close()


def valid_email(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None

def sendVerificationMail(email, token):
    if not valid_email(email):
        return 0

    verification_link = url_for(
        "verify_email",
        token=token,
        _external=True
    )

    msg = Message(
        subject="Verify your TournamentHub account",
        recipients=[email]
    )

    msg.body = f"""Hello,

Thank you for signing up for TournamentHub.

Please verify your email address by clicking the link below:

{verification_link}

If you did not create a TournamentHub account, you can ignore this email.

TournamentHub
"""

    try:
        mail.send(msg)
        return token

    except Exception as e:
        return 0
    
@app.route("/verify_email/<token>")
def verify_email(token):
    db, cursor = get_db_connection()
    try:
        cursor.execute('SELECT * FROM email_verification_tokens WHERE token = %s', (token,))
        email_verification_token = cursor.fetchone()
        if not email_verification_token:
            abort(404)
        userid = email_verification_token['userId']
        cursor.execute("UPDATE users SET email_verified = 1 WHERE id = %s", (userid,))
        db.commit()
        tokenId = email_verification_token['id']
        cursor.execute('DELETE FROM email_verification_tokens WHERE id = %s', (tokenId,))
        db.commit()
    finally:
        cursor.close()
        db.close()
    return redirect(url_for('login'))

@app.route("/signup", methods=['POST', "GET"])
def signup():
    error = ""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get("password")
        email = request.form.get('email')
        if not valid_email(email):
            return render_template("signup.html",error="Please enter a valid email address.")

        
        if not username or not password or not email:
            return render_template('signup.html', error="email, username or password missing")

        db, cursor = get_db_connection()

        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return render_template('signup.html', error="username taken")
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return render_template('signup.html', error="email in use")
            password_hash = generate_password_hash(password)
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, email)
                VALUES (%s, %s, %s)
                """,
                (username, password_hash, email)
            )
            db.commit()
            userid = cursor.lastrowid
            token = makeToken()
            cursor.execute('INSERT INTO email_verification_tokens (userId, token) VALUES (%s, %s)', (userid, token))
            db.commit()
            sendVerificationMail(email, token)
            return redirect(url_for('login'))
        finally:
            cursor.close()
            db.close()

    return render_template('signup.html', error=error)
    
@app.route("/tournaments")
def tournaments():
    userid = session.get("userid")

    db, cursor = get_db_connection()

    try:
        cursor.execute(
            """
            SELECT
                ft.sortOrder,
                tg.id AS tag_id,
                tg.name AS tag_name,

                t.id AS tournament_id,
                t.name AS tournament_name,
                t.code,
                t.visibility,
                t.verified,
                t.created_at,
                t.status

            FROM featured_tags AS ft
            JOIN tags AS tg
                ON tg.id = ft.tagId

            LEFT JOIN tournament_tags AS tt
                ON tt.tagId = tg.id

            LEFT JOIN tournaments AS t
                ON t.id = tt.tournamentId
                AND (
                    t.visibility = 'public'
                )

            ORDER BY
                ft.sortOrder ASC,
                t.verified DESC,
                t.name ASC
            """
        )

        rows = cursor.fetchall()

    finally:
        cursor.close()
        db.close()

    categories = []
    category_map = {}

    for row in rows:
        tag_id = row["tag_id"]

        if tag_id not in category_map:
            category = {
                "name": row["tag_name"],
                "icon": '',
                "tournaments": []
            }

            category_map[tag_id] = category
            categories.append(category)

        # Een featured tag zonder toernooien blijft zichtbaar.
        if row["tournament_id"] is not None:
            category_map[tag_id]["tournaments"].append({
                "id": row["tournament_id"],
                "name": row["tournament_name"],
                "code": row["code"],
                "visibility": row["visibility"],
                "is_official": bool(row["verified"]),
                "created_at": row["created_at"],
                "status" : row['status']
            })

    return render_template(
        "tournaments.html",
        categories=categories,
        userid=userid
    )

@app.route("/generateschedule/<tournamentCode>", methods=['POST', 'GET'])
def generateSchedule(tournamentCode):
    userid = session.get('userid')
    db, cursor = get_db_connection()

    # Tournament + rounds ophalen
    cursor.execute("""
        SELECT
            rounds.id AS round_id,
            rounds.name AS round_name,
            rounds.roundNumber,
            tournaments.name AS tournament_name
        FROM rounds
        JOIN tournaments
            ON rounds.tournamentId = tournaments.id
        WHERE tournaments.code = %s
        ORDER BY rounds.roundNumber ASC
    """, (tournamentCode,))

    round_rows = cursor.fetchall()

    rounds = []

    for row in round_rows:

        round_data = {
            "id": row["round_id"],
            "name": row["round_name"],
            "roundNumber": row["roundNumber"],
            "tournamentName": row["tournament_name"],
            "games": []
        }

        cursor.execute("""
            SELECT
                games.id,
                games.location,
                games.start_time,
                games.status
            FROM games
            WHERE games.roundId = %s
            ORDER BY games.start_time ASC
        """, (row["round_id"],))

        games = cursor.fetchall()

        for game in games:

            cursor.execute("""
                SELECT
                    teams.id,
                    teams.name,
                    scores.score,
                    scores.result
                FROM game_teams
                JOIN teams
                    ON teams.id = game_teams.teamId
                LEFT JOIN scores
                    ON scores.gameId = game_teams.gameId
                    AND scores.teamId = game_teams.teamId
                WHERE game_teams.gameId = %s
            """, (game["id"],))

            teams = cursor.fetchall()

            game_data = {
                "id": game["id"],
                "location": game["location"],
                "start_time": game["start_time"],
                "status": game["status"],
                "teams": teams
            }

            round_data["games"].append(game_data)

        rounds.append(round_data)

    cursor.close()
    db.close()

    return render_template(
        "generateschedule.html",
        rounds=rounds,
        userid=userid
    )

@app.route("/tournament/id/<id>")
@app.route("/tournament/code/<code>")
def tournament(code='', id=''):
    userid = session.get("userid")

    db, cursor = get_db_connection()

    try:
        cursor.execute(
            "SELECT * FROM tournaments WHERE code = %s or id = %s",
            (code, id)
        )

        tournament = cursor.fetchone()
        
        if not tournament:
            abort(404)

        cursor.execute("""
            SELECT *
            FROM rounds
            WHERE tournamentId = %s
            ORDER BY roundNumber ASC
        """, (tournament["id"],))

        rounds = cursor.fetchall()

        cursor.execute("""
            SELECT
                games.id AS gameId,
                games.start_time,
                stadiums.name AS location,
                games.roundId,
                games.status,

                teams.id AS teamId,
                teams.name AS teamName,

                scores.score,
                scores.result

            FROM games

            JOIN game_teams
                ON game_teams.gameId = games.id

            JOIN teams
                ON teams.id = game_teams.teamId

            LEFT JOIN scores
                ON scores.gameId = games.id
                AND scores.teamId = teams.id

            LEFT JOIN stadiums
                ON stadiums.id = games.stadiumId
                
            WHERE games.roundId IN (
                SELECT id
                FROM rounds
                WHERE tournamentId = %s
            )

            ORDER BY
                games.start_time ASC,
                games.id ASC,
                game_teams.id ASC
        """, (tournament["id"],))

        game_rows = cursor.fetchall()

        games_by_round = {}

        for row in game_rows:
            game_id = row["gameId"]

            if game_id not in games_by_round:
                games_by_round[game_id] = {
                    "id": game_id,
                    "start_time": row["start_time"],
                    "location": row["location"],
                    "roundId": row["roundId"],
                    "status": row["status"],
                    "teams": []
                }

            games_by_round[game_id]["teams"].append({
                "id": row["teamId"],
                "name": row["teamName"],
                "score": row["score"],
                "result": row["result"]
            })

        for round in rounds:
            round["games"] = []

            for game in games_by_round.values():
                if game["roundId"] == round["id"]:
                    round["games"].append(game)
        permissions = can_user(userid)
        return render_template(
            "tournament.html",
            tournament=tournament,
            rounds=rounds,
            userid=userid,
            permissions=permissions
        )

    finally:
        cursor.close()
        db.close()

@app.route("/delete-game/<gameId>")
@login_required
def deleteGame(gameId):
    userid = session.get('userid')
    db, cursor = get_db_connection()
    try:
        cursor.execute(
            """SELECT t.code, t.id AS tournamentId
            FROM tournaments as t
            JOIN rounds as r ON r.tournamentId = t.id
            JOIN games as g ON r.id = g.roundId
            WHERE g.id = %s
            """, (gameId,)
                       )
        game = cursor.fetchone()
        if not game:
            abort(404)
        if not can_user(userid, 'tournament.delete_games', game['tournamentId']):
            flash("Je hebt geen toestemming om wedstrijd van dit tournament te verwijderen.", "error")
            return redirect(request.referrer or url_for('tournament', code = game['code']))
        
        cursor.execute('DELETE FROM games WHERE id = %s', (gameId,))
        db.commit()
        code = game.get('code')
        return redirect(url_for('tournament', code=code))
    finally:
        cursor.close()
        db.close()

@app.route('/round/<int:round_id>/delete', methods=['POST'])
def delete_round(round_id):
    db, cursor = get_db_connection()

    cursor.execute("""
        SELECT r.id, t.code, t.id AS tournamentId
        FROM rounds r
        JOIN tournaments t ON t.id = r.tournamentId
        WHERE r.id = %s
    """, (round_id,))

    round_data = cursor.fetchone()

    if not round_data:
        cursor.close()
        return "Round not found", 404
    userid = session.get('userid')
    if not can_user(userid, 'tournament.delete_rounds', round_data['tournamentId']):
        flash("Je hebt geen toestemming om de ronde van dit tournament te verwijderen.", "error")
        return redirect(request.referrer or url_for('tournament', code = round_data['code']))
  
    cursor.execute(
        "DELETE FROM games WHERE roundId = %s",
        (round_id,)
    )

    cursor.execute(
        "DELETE FROM rounds WHERE id = %s",
        (round_id,)
    )

    db.commit()
    cursor.close()

    return redirect(url_for('tournament', code=round_data['code']))

def updatePoints(gameId, cursor, db):
    # Controleer of de wedstrijd bestaat en completed is
    cursor.execute("""
        SELECT status
        FROM games
        WHERE id = %s
    """, (gameId,))

    game = cursor.fetchone()

    if not game or game["status"] != "completed":
        return

    # Alle voorspellingen voor deze wedstrijd ophalen
    cursor.execute("""
        SELECT id, userId
        FROM predictions
        WHERE gameId = %s
    """, (gameId,))

    predictions = cursor.fetchall()

    # Voor iedere voorspelling de punten berekenen
    for prediction in predictions:

        scores = calc_prediction_points_game(
            gameId,
            prediction["userId"],
            cursor
        )

        total_points = scores["total"]

        # Totale punten opslaan
        cursor.execute("""
            UPDATE predictions
            SET points = %s
            WHERE id = %s
        """, (
            total_points,
            prediction["id"]
        ))

    db.commit()


@app.route("/edit_tournament/<tournamentId>", methods=['GET'])
@login_required
def editTournament(tournamentId):
    db, cursor = get_db_connection()
    userId= session.get('userid')
    if not can_user(userId, 'tournament.edit', tournamentId):
        flash("Je hebt geen toestemming om de ronde van dit tournament te wijzigen.", "error")
        return redirect(request.referrer or url_for('tournament', id = tournamentId))

        
    try:
        cursor.execute("""
            SELECT id, name, visibility, code, created_at, verified
            FROM tournaments AS t
            WHERE t.id = %s
        """, (tournamentId,))
        tournament = cursor.fetchone()
        cursor.execute("""
            SELECT id, name, verified
            FROM tags
            JOIN tournament_tags ON tags.id = tournament_tags.tagId
            WHERE tournament_tags.tournamentId = %s
        """, (tournamentId,))
        tags = cursor.fetchall()
        tournament["tags"] = tags
        
        return render_template('edittournament.html', tournament=tournament, userid=userId)
    finally:
        cursor.close()
        db.close()

@app.route("/game/<int:game_id>/edit", methods=["GET", "POST"])
@login_required
def edit_game(game_id):
    userid = session.get("userid")

    db, cursor = get_db_connection()
    
    try:
        cursor.execute("""
            SELECT
                games.*,
                tournaments.id AS tournamentId,
                tournaments.name AS tournament_name,
                tournaments.code
            FROM games
            JOIN rounds 
                ON rounds.id = games.roundId
            JOIN tournaments 
                ON tournaments.id = rounds.tournamentId
            WHERE games.id = %s
	    LIMIT 1
        """, (game_id,))

        game = cursor.fetchone()

        if not game:
            abort(404)

        if not can_user(userid, 'tournament.edit_games', game['tournamentId']):
            flash("Je hebt geen toestemming om deze wedstrijd te bewerken.", "error")
            return redirect(request.referrer or url_for("tournament", code=game["code"]))


        tournament = {
            "id": game["tournamentId"],
            "name": game["tournament_name"],
            "code": game["code"]
        }


        # Rounds ophalen
        cursor.execute("""
            SELECT id, name, roundNumber
            FROM rounds
            WHERE tournamentId = %s
            ORDER BY roundNumber
        """, (game["tournamentId"],))

        rounds = cursor.fetchall()



        if request.method == "POST":

            round_id = request.form.get("roundId")
            start_time = request.form.get("start_time") or None
            location = request.form.get("location") or None
            status = request.form.get("status") or "scheduled"

            team1_id = request.form.get("team1")
            team2_id = request.form.get("team2")


            if not team1_id or not team2_id:
                raise Exception("Two teams are required")

            if team1_id == team2_id:
                raise Exception("Teams cannot be the same")


            # Check ronde
            cursor.execute("""
                SELECT id
                FROM rounds
                WHERE id = %s
                AND tournamentId = %s
            """, (
                round_id,
                game["tournamentId"]
            ))

            if not cursor.fetchone():
                abort(400)



            # Check teams eigenaar
            cursor.execute("""
                SELECT id
                FROM teams
                WHERE id IN (%s,%s)
                AND tournamentId = %s
            """, (
                team1_id,
                team2_id,
                tournament['id']
            ))

            teams = cursor.fetchall()

            if len(teams) != 2:
                abort(403)

            stadiumId = None
            if location:
                cursor.execute('SELECT id FROM stadiums WHERE LOWER(name) = LOWER(%s) AND tournamentId = %s LIMIT 1', (location, userid))
                stadium = cursor.fetchone()
                if stadium:
                    stadiumId = stadium['id']
                else:
                    cursor.execute('INSERT INTO stadiums (name, tournamentId) VALUES (%s, %s)', (location, tournament['id']))
                    db.commit()
                    stadiumId = cursor.lastrowid
            # Game updaten
            cursor.execute("""
                UPDATE games
                SET
                    roundId = %s,
                    start_time = %s,
                    stadiumId = %s,
                    status = %s
                WHERE id = %s
            """, (
                round_id,
                start_time,
                stadiumId,
                status,
                game_id
            ))

            

            # Oude teams verwijderen
            cursor.execute("""
                DELETE FROM game_teams
                WHERE gameId = %s
            """, (game_id,))


            # Nieuwe teams toevoegen
            cursor.execute("""
                INSERT INTO game_teams
                    (gameId, teamId, home_away)
                VALUES
                    (%s,%s, 'home'),
                    (%s,%s, 'away')
            """, (
                game_id,
                team1_id,
                game_id,
                team2_id
            ))



            # Scores verwijderen die niet meer bestaan
            cursor.execute("""
                DELETE FROM scores
                WHERE gameId = %s
                AND teamId NOT IN (%s,%s)
            """, (
                game_id,
                team1_id,
                team2_id
            ))



            # Nieuwe scores maken als ze ontbreken
            for team_id in [team1_id, team2_id]:

                cursor.execute("""
                    SELECT id
                    FROM scores
                    WHERE gameId = %s
                    AND teamId = %s
		    LIMIT 1
                """, (
                    game_id,
                    team_id
                ))

                exists = cursor.fetchone()

                if not exists:
                    cursor.execute("""
                        INSERT INTO scores
                            (gameId, teamId, score, result)
                        VALUES
                            (%s,%s,0,NULL)
                    """, (
                        game_id,
                        team_id
                    ))



            # Scores opslaan
            cursor.execute("""
                SELECT id
                FROM scores
                WHERE gameId = %s
            """, (game_id,))

            current_scores = cursor.fetchall()


            # Scores uit formulier ophalen
            scores_data = {}

            for score in current_scores:
                value = request.form.get(f"score_{score['id']}")

                if value is not None:
                    scores_data[score["id"]] = int(value)

            # Alleen bepalen als er precies 2 teams zijn
            if len(scores_data) == 2:
                score_ids = list(scores_data.keys())

                score1 = scores_data[score_ids[0]]
                score2 = scores_data[score_ids[1]]

                if score1 > score2:
                    results = {
                        score_ids[0]: "won",
                        score_ids[1]: "lost"
                    }
                elif score1 < score2:
                    results = {
                        score_ids[0]: "lost",
                        score_ids[1]: "won"
                    }
                else:
                    results = {
                        score_ids[0]: "draw",
                        score_ids[1]: "draw"
                    }

                for score_id in score_ids:
                    cursor.execute("""
                        UPDATE scores
                        SET
                            score = %s,
                            result = %s
                        WHERE id = %s
                    """, (
                        scores_data[score_id],
                        results[score_id],
                        score_id
                    ))
            if status == 'completed':

                updatePoints(game_id, cursor, db)
            db.commit()

            return redirect(
                url_for(
                    "tournament",
                    code=game["code"]
                )  + f'#{game['id']}'
            )
        # Teams ophalen voor pagina
        cursor.execute("""
            SELECT
                teams.id,
                teams.name
            FROM game_teams
            JOIN teams
                ON teams.id = game_teams.teamId
            WHERE game_teams.gameId = %s
            ORDER BY game_teams.id
        """, (game_id,))

        game_teams = cursor.fetchall()

        team1 = game_teams[0] if len(game_teams) > 0 else None
        team2 = game_teams[1] if len(game_teams) > 1 else None



        # Scores ophalen
        cursor.execute("""
            SELECT
                scores.id,
                scores.teamId,
                scores.score,
                scores.result,
                teams.name AS team_name
            FROM scores
            JOIN teams
                ON teams.id = scores.teamId
            WHERE scores.gameId = %s
        """, (game_id,))

        scores = cursor.fetchall()
        cursor.execute("""
            SELECT COALESCE(s.name, '') AS location
            FROM games g
            LEFT JOIN stadiums s ON s.id = g.stadiumId
            WHERE g.id = %s
	    LIMIT 1
        """, (game_id,))

        game['stadiumName'] = cursor.fetchone()['location']
        
        return render_template(
            "editgame.html",
            game=game,
            rounds=rounds,
            scores=scores,
            team1=team1,
            team2=team2,
            tournament=tournament,
            userid=userid
        )


    except Exception:
        db.rollback()
        raise


    finally:
        cursor.close()
        db.close()

def get_code():
    db, cursor = get_db_connection()

    try:
        while True:
            code = ''.join(
                random.choices(
                    string.ascii_uppercase + string.digits,
                    k=8
                )
            )

            cursor.execute(
                "SELECT id FROM tournaments WHERE code = %s",
                (code,)
            )

            tournament = cursor.fetchone()

            if not tournament:
                return code

    finally:
        cursor.close()
        db.close()

def get_lobby_code():
    db, cursor = get_db_connection()

    try:
        while True:
            code = ''.join(
                random.choices(
                    string.ascii_uppercase + string.digits,
                    k=8
                )
            )

            cursor.execute(
                "SELECT id FROM lobbies WHERE code = %s",
                (code,)
            )

            lobby = cursor.fetchone()

            if not lobby:
                return code

    finally:
        cursor.close()
        db.close()

@app.route('/tournament/<int:tournament_id>/delete', methods=['POST'])
@login_required
def delete_tournament(tournament_id):
    db, cursor = get_db_connection()
    userid = session.get('userid')
    if not can_user(userid, 'tournament.delete', tournament_id):
        flash("Je hebt geen toestemming om dit tournament te verwijderen.", "error")
        return redirect(request.referrer or url_for("tournament", id=tournament_id))
    cursor.execute(
        'DELETE FROM tournaments WHERE id = %s',
        (tournament_id,)
    )

    db.commit()
    cursor.close()

    return redirect(url_for('myTournaments'))

def isOwnerTournament(userId, tournamentId, cursor):
    cursor.execute("SELECT makerid FROM tournaments WHERE id = %s AND makerid = %s", (tournamentId, userId))
    tournament = cursor.fetchone()
    if tournament:
        return True
    else:
        return False

def insertTag(tagName, verified, cursor, db):
    if verified:
        verified = 1
    else:
        verified = 0
    cursor.execute("INSERT INTO tags (name, verified) VALUES (%s, %s)", (tagName, verified))

    db.commit()

    tagId = cursor.lastrowid

    if cursor.rowcount == 1:
        return tagId

    return None

def isUserVerified(userid, cursor):
    cursor.execute('SELECT is_verified FROM users WHERE id = %s', (userid,))
    user = cursor.fetchone()
    if not user:
        return None
    verified = user['is_verified']
    return bool(verified)

def get_tagId_tagName(name, cursor):
    cursor.execute("SELECT id FROM tags WHERE name = %s", (name,))
    tag = cursor.fetchone()
    if not tag:
        return None
    tagId = tag['id']
    return tagId

def insertTagTournament(tagId, tournamentId, cursor, db):
    try:
        cursor.execute(
            """
            INSERT INTO tournament_tags (tournamentId, tagId)
            VALUES (%s, %s)
            """,
            (tournamentId, tagId)
        )

        db.commit()

        return True

    except Exception as e:
        db.rollback()
        return False


def updateTag(userid, tournamentId, tag, cursor, db):
    tagId = None
    cursor.execute("""
        SELECT *
        FROM tags
        WHERE name = %s
    """, (tag,))
    tag2 = cursor.fetchone()
    if not tag2:
        verified = isUserVerified(userid,cursor)

        tagId = insertTag(tag, verified, cursor, db)

    if not tagId:
        tagId = get_tagId_tagName(tag, cursor)

    cursor.execute('SELECT * FROM tournament_tags WHERE tagId = %s', (tagId,))
    tournament_tag = cursor.fetchone()
    if not tournament_tag:
        insertTagTournament(tagId, tournamentId, cursor, db)

    
def deleteTagsTournament(tags, tournamentId, userId, db, cursor):
    
    if not isOwnerTournament(userId, tournamentId, cursor):
        return None

    cursor.execute("""
        SELECT * FROM tournament_tags
        JOIN tags ON tournament_tags.tagId = tags.id
        WHERE tournamentId = %s
    """, (tournamentId,))
    tournament_tags = cursor.fetchall()
    for tournament_tag in tournament_tags:

        if tournament_tag["name"] not in tags:
            tagId = get_tagId_tagName(tournament_tag['name'], cursor)
            cursor.execute('DELETE FROM tournament_tags WHERE tagId = %s AND tournamentId = %s', (tagId, tournamentId))
            db.commit()

def deleteTagTournament(tagId, tournamentId, cursor, db):
    cursor.execute("DELETE FROM tournament_tags WHERE tagId = %s AND tournamentId = %s", (tagId, tournamentId))
    db.commit()

def fetch_Tags_Tournament(tournamentId, cursor):
    cursor.execute("""
        SELECT *
        FROM tags
        JOIN tournament_tags AS t_tags ON tags.id = t_tags.tagId
        JOIN tournaments AS t ON t_tags.tournamentId = t.id
        WHERE t.id = %s
    """, (tournamentId,))
    tournament_tags = cursor.fetchall()
    return tournament_tags

def makeTag(tag, cursor, db):
    cursor.execute("INSERT INTO tags (name) VALUES (%s)", (tag,))
    db.commit()

def manageTags(tags, tournamentId, userId, db, cursor):
    cursor.execute(
        'DELETE FROM tournament_tags WHERE tournamentId = %s',
        (tournamentId,)
    )

    for tag in tags:
        tagId = get_tagId_tagName(tag, cursor)

        if not tagId:
            makeTag(tag, cursor, db)
            tagId = get_tagId_tagName(tag, cursor)

        insertTagTournament(tagId, tournamentId, cursor, db)





@app.route("/editTournament/<tournamentId>", methods=['POST'])
@login_required
def editTournamentPost(tournamentId):
    userId = session.get('userid')
    db, cursor = get_db_connection()
    if not can_user(userId, 'tournament.edit', tournamentId):
        flash("Je hebt geen toestemming om dit tournament te bewerken.", "error")
        return redirect(request.referrer or url_for("tournament", id=tournamentId))

    tags = request.form.get('tags')
    tags = tags.split(",")
    #editTags(tags, tournamentId, userId, db, cursor)
    #deleteTagsTournament(tags, tournamentId, userId, db, cursor)
    manageTags(tags, tournamentId, userId, db, cursor)

    visibility = request.form.get('visibility')
    cursor.execute("UPDATE tournaments SET visibility = %s WHERE id = %s", (visibility, tournamentId))
    db.commit()

    tournamentName = request.form.get('name')
    cursor.execute("UPDATE tournaments SET name = %s WHERE id = %s", (tournamentName, tournamentId))
    db.commit()


    cursor.close()
    db.close()
    return redirect(url_for('myTournaments'))


def editTags(tags, tournamentId, userId, db, cursor):
    
    if not isOwnerTournament(userId, tournamentId, cursor):
        return 0

    for tag in tags:
        updateTag(userId, tournamentId, tag, cursor, db)

@app.route("/findtournament", methods=["GET", "POST"])
def findTournament():
    error = ""
    userid = session.get('userid')
    if request.method == "POST":
        code = request.form.get('code')

        db, cursor = get_db_connection()
        try:
            cursor.execute('SELECT * FROM tournaments WHERE code = %s', (code,))
            tournament = cursor.fetchone()
            if not tournament:
                return render_template('findtournament.html', userid=userid, error="tournament not found")
            return redirect(url_for('tournament', code=tournament.get('code')))
        finally:
            cursor.close()
            db.close()

    return render_template('findtournament.html', userid=userid, error = error)

@app.route("/makegame/<int:roundId>", methods=["POST", "GET"])
@login_required
def makeGame(roundId):
    userid = session.get("userid")

    db, cursor = get_db_connection()

    try:
        cursor.execute("""
            SELECT
                rounds.id,
                rounds.tournamentId,
                tournaments.code
            FROM rounds
            JOIN tournaments
                ON tournaments.id = rounds.tournamentId
            WHERE rounds.id = %s
        """, (roundId,))
	
        round_data = cursor.fetchone()

        if not round_data:
            abort(404)

        if not can_user(userid, 'tournament.create_games', round_data['tournamentId']):
            flash("Je hebt geen toestemming om games in dit tournament te maken.", "error")
            return redirect(request.referrer or url_for("tournament", id=round_data['tournamentId']))


        if request.method == "POST":
            team1 = request.form.get("team1")
            team2 = request.form.get("team2")
            start_time = request.form.get("start_time")
            location = request.form.get("location")

            if not team1 or not team2:
                return render_template(
                    "makegame.html",
                    roundId=roundId,
                    error="Select two teams."
                )

            if team1 == team2:
                return render_template(
                    "makegame.html",
                    roundId=roundId,
                    error="A team cannot play against itself."
                )

            cursor.execute("""
                SELECT id
                FROM teams
                WHERE id IN (%s, %s)
                AND tournamentId = %s
            """, (
                team1,
                team2,
                round_data['tournamentId']
            ))

            teams = cursor.fetchall()

            if len(teams) != 2:
                abort(403)

            stadiumId = None
            if location:
                cursor.execute("""
                    SELECT id
                    FROM stadiums
                    WHERE tournamentId = %s AND LOWER(name) = LOWER(%s)
                """, (userid, location))
                stadium = cursor.fetchone()
                if stadium:
                    stadiumId = stadium['id']
                if not stadiumId:
                    cursor.execute('INSERT INTO stadiums (tournamentId, name) VALUES (%s, %s)', (round_data['tournamentId'], location))
                    db.commit()
                    stadiumId = cursor.lastrowid

            cursor.execute("""
                INSERT INTO games (
                    start_time,
                    stadiumId,
                    roundId
                )
                VALUES (%s, %s, %s)
            """, (
                start_time if start_time else None,
                stadiumId if stadiumId else None,
                roundId
            ))

            game_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO game_teams (
                    gameId,
                    teamId,
                    home_away
                )
                VALUES (%s, %s, 'home')
            """, (
                game_id,
                team1
            ))

            cursor.execute("""
                INSERT INTO game_teams (
                    gameId,
                    teamId,
                    home_away
                )
                VALUES (%s, %s, 'away')
            """, (
                game_id,
                team2
            ))

            # Voor beide teams een score aanmaken
            cursor.execute("""
                INSERT INTO scores (gameId, teamId, score, result)
                VALUES
                    (%s, %s, 0, NULL),
                    (%s, %s, 0, NULL)
            """, (
                game_id,
                team1,
                game_id,
                team2
            ))

            db.commit()

            return redirect(
                url_for(
                    "tournament",
                    code=round_data["code"]
                )
            )

        return render_template(
            "makegame.html",
            roundId=roundId, userid=userid, tournamentId = round_data['tournamentId']
        )

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()
        db.close()

@app.route("/make", methods=["POST", "GET"])
def make():
    userid = session.get("userid")

    if not userid:
        abort(401)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        visibility = request.form.get("visibility")
        raw_tags = request.form.get("tags", "")

        # "test,haha" wordt ["test", "haha"]
        tag_names = []
        for tag in raw_tags.split(","):
            tag = tag.strip()

            if tag and tag not in tag_names:
                tag_names.append(tag)

        db, cursor = get_db_connection()

        try:
            code = get_code()

            cursor.execute(
                """
                INSERT INTO tournaments (name, visibility, code)
                VALUES (%s, %s, %s)
                """,
                (name, visibility, code)
            )
            tournament_id = cursor.lastrowid
            cursor.execute("INSERT INTO user_roles (roleId, scopeId, scopeType, userId) VALUES ('2', %s, 'tournament', %s)", (tournament_id, userid))
            tournament_id = cursor.lastrowid

            for tag_name in tag_names:
                # Bestaande tags blijven behouden; nieuwe tags zijn standaard
                # niet geverifieerd.
                cursor.execute(
                    "INSERT IGNORE INTO tags (name) VALUES (%s)",
                    (tag_name,)
                )

                cursor.execute(
                    "SELECT id FROM tags WHERE name = %s",
                    (tag_name,)
                )
                tag = cursor.fetchone()

                cursor.execute(
                    """
                    INSERT IGNORE INTO tournament_tags (tournamentId, tagId)
                    VALUES (%s, %s)
                    """,
                    (tournament_id, tag["id"])
                )

            db.commit()

        finally:
            cursor.close()
            db.close()

        return redirect(url_for("tournament", code=code))
    ##return render_template("maketournament/main.html", userid=userid)
    return render_template("make.html", userid=userid)

@app.route("/my-tournaments")
@login_required
def myTournaments():
    userid = session.get('userid')
    db, cursor = get_db_connection()
    try:
        cursor.execute("""
            SELECT tournaments.*
            FROM tournaments
            JOIN user_roles
                ON user_roles.scopeType = 'tournament' AND user_roles.scopeId = tournaments.id
            WHERE user_roles.userId = %s
            
        """, (userid,))
        tournaments  = cursor.fetchall()
    finally:
        cursor.close()
        db.close()
    return render_template('mytournaments.html', userid=userid, tournaments=tournaments)

@app.route("/profile")
@login_required
def profile():
    userid = session.get('userid')
    return render_template('profile.html', userid=userid)

@app.route("/changepassword", methods=["POST"])
@login_required
def changePassword():
    userid =  session.get('userid')
    currentPassword = request.form.get('currentPassword')
    newPassword = request.form.get('newPassword')
    repeatPassword = request.form.get('repeatPassword')

    if newPassword != repeatPassword:
        abort(404)

    db, cursor = get_db_connection()
    try:
        cursor.execute("SELECT password_hash FROM users WHERE id = %s", (userid,))
        user = cursor.fetchone()
        if not user:
            abort(404)
        password_hash = user['password_hash']
        if not check_password_hash(password_hash, currentPassword):
            abort(403)
        newPassword_hash = generate_password_hash(newPassword)
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (newPassword_hash, userid))
        db.commit()
        return redirect(url_for('profile'))
    finally:
        cursor.close()
        db.close()

@app.route("/makeround/<int:id>", methods=["POST", "GET"])
@login_required
def makeRound(id):
    userid = session.get('userid')
    if request.method == "POST":
        name = request.form.get('name')
        roundNumber = request.form.get('roundNumber')
        db, cursor = get_db_connection()
        try:
            cursor.execute('SELECT code FROM tournaments WHERE id = %s', (id,))
            tournament = cursor.fetchone()
            if not can_user(userid,'tournament.create_rounds', id):
                flash("Je hebt geen toestemming om rondes in dit tournament te maken.", "error")
                return redirect(request.referrer or url_for("tournament", code=tournament['code']))

            cursor.execute('INSERT INTO rounds (name, tournamentId, roundNumber) VALUES (%s,%s,%s)', (name, id, roundNumber))
            db.commit()
            return redirect(url_for('tournament', code=tournament["code"]))
        finally:
            cursor.close()
            db.close()
            
    return render_template('makeround.html', userid=userid)

def get_tournament_rounds(tournament_id, userid=None):
    db, cursor = get_db_connection()

    try:
        cursor.execute("""
            SELECT *
            FROM rounds
            WHERE tournamentId = %s
            ORDER BY roundNumber ASC
        """, (tournament_id,))

        rounds = cursor.fetchall()


        cursor.execute("""
            SELECT
                games.id AS gameId,
                games.start_time,
                stadiums.name AS location,
                games.roundId,
                games.status,

                teams.id AS teamId,
                teams.name AS teamName,

                scores.score AS teamScore,
                scores.result AS teamResult,

                predicted_scores.score AS predictedScore

            FROM games

            JOIN game_teams
                ON game_teams.gameId = games.id

            JOIN teams
                ON teams.id = game_teams.teamId

            LEFT JOIN scores
                ON scores.gameId = games.id
                AND scores.teamId = teams.id

            LEFT JOIN predictions
                ON predictions.gameId = games.id
                AND predictions.userId = %s

            LEFT JOIN predicted_scores
                ON predicted_scores.predictionId = predictions.id
                AND predicted_scores.teamId = teams.id

            LEFT JOIN stadiums
                ON stadiums.id = games.stadiumId

            WHERE games.roundId IN (
                SELECT id
                FROM rounds
                WHERE tournamentId = %s
            )

            ORDER BY
                games.start_time ASC,
                games.id ASC,
                game_teams.id ASC
        """, (userid, tournament_id))


        game_rows = cursor.fetchall()

        games_by_id = {}


        for row in game_rows:

            if row["gameId"] not in games_by_id:
                games_by_id[row["gameId"]] = {
                    "id": row["gameId"],
                    "start_time": row["start_time"],
                    "location": row["location"],
                    "roundId": row["roundId"],
                    "status": row["status"],
                    "teams": []
                }


            games_by_id[row["gameId"]]["teams"].append({
                "id": row["teamId"],
                "name": row["teamName"],
                "score": row["teamScore"],
                "result": row["teamResult"],
                "predictedScore": row["predictedScore"]
            })


        for round in rounds:
            round["games"] = []

            for game in games_by_id.values():
                if game["roundId"] == round["id"]:
                    round["games"].append(game)

        ## for game in games_by_id.values():
        ##   print(game["id"], game["status"], game["teams"])
        return rounds


    finally:
        cursor.close()
        db.close()



@app.route("/lobbies")
@app.route("/lobbies/<code>")
@login_required
def lobbies(code=None):
    userid = session.get('userid')
    db, cursor = get_db_connection()
    try:
        cursor.execute('SELECT * FROM lobby_members as lm JOIN lobbies AS l ON lm.lobbyId = l.id WHERE userId = %s', (userid,))
        lobbies = cursor.fetchall()
        return render_template('lobbies.html', tournament_code=code or "", userid=userid, lobbies=lobbies)
    finally:
        cursor.close()
        db.close()

@app.route('/lobby/<code>')
@login_required
def lobby(code):
    userid = session.get('userid')

    db, cursor = get_db_connection()

    try:
        cursor.execute(
            "SELECT * FROM lobbies WHERE code = %s",
            (code,)
        )

        lobby = cursor.fetchone()

        if not lobby:
            abort(404)


        cursor.execute(
            "SELECT * FROM tournaments WHERE id = %s",
            (lobby['tournamentId'],)
        )

        tournament = cursor.fetchone()

        if not tournament:
            abort(404)

        
        
        leaderboard, status, error_code = get_lobby_leaderboard(lobbyCode=code, cursor=cursor)

        if status == 'error':
            error_msg = leaderboard
            flash(error_msg, "error")
            return redirect(request.referrer or abort(error_code))
        
        rounds_points = get_lobby_rounds_points(lobby["id"],userid, cursor)
    finally:
        cursor.close()
        db.close()


    rounds = get_tournament_rounds(tournament["id"], userid)
    
    
    for round in rounds:
        for round_points in rounds_points:
            if round["id"] == round_points["id"]:
                round["points"] = round_points["points"]
                break
    

        

    return render_template(
        'lobby.html',
        userid=userid,
        lobby=lobby,
        tournament=tournament,
        rounds=rounds,
        leaderboard=leaderboard
    )



@app.route("/joinlobby", methods=['POST'])
@login_required
def joinLobby():
    db, cursor = get_db_connection()
    userid = session.get('userid')
    try:
        code = request.form.get('code')
        cursor.execute('SELECT * FROM lobbies WHERE code=%s', (code,))
        lobby = cursor.fetchone()
        if not lobby:
            abort(404)
        if lobby['isPrivate'] == 1:
            password = request.form.get('password')
            if lobby['password'] != password:
                abort(401)
        cursor.execute('SELECT * FROM lobby_members WHERE userid = %s AND lobbyId = %s', (userid, lobby['id']))
        isMember = cursor.fetchone()
        if isMember:
            return redirect(url_for('lobby', code=lobby['code']))
        cursor.execute('INSERT INTO lobby_members (lobbyId, userId) VALUES (%s, %s)', (lobby['id'], userid))
        db.commit()
        return redirect(url_for('lobby', code=lobby['code']))
    finally:
        cursor.close()
        db.close()

@app.route('/createlobby', methods=['POST'])
@login_required
def createLobby():
    userid = session.get('userid')

    db, cursor = get_db_connection()

    try:
        tournament_code = request.form.get('tournament_code')
        name = request.form.get('name')
        password = request.form.get('password')

        cursor.execute(
            'SELECT id FROM tournaments WHERE code = %s',
            (tournament_code,)
        )

        tournament = cursor.fetchone()

        if not tournament:
            abort(404)

        tournamentId = tournament['id']

        isPrivate = bool(password)

        lobbyCode = get_lobby_code()

        cursor.execute(
            '''
            INSERT INTO lobbies 
            (tournamentId, name, code, isPrivate, password, makerId)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''',
            (
                tournamentId,
                name,
                lobbyCode,
                isPrivate,
                password if isPrivate else None,
                userid
            )
        )

        lobbyId = cursor.lastrowid

        cursor.execute("INSERT INTO user_roles (userId, roleId, scopeType, scopeId) VALUES (%s, 5, 'lobby', %s)", (userid, lobbyId))
        cursor.execute(
            '''
            INSERT INTO lobby_members
            (lobbyId, userId)
            VALUES (%s, %s)
            ''',
            (
                lobbyId,
                userid
            )
        )

        db.commit()

        cursor.execute('INSERT INTO lobby_points_rules (lobbyId) VALUES (%s)', (lobbyId,))
        db.commit()

        return redirect(
            url_for('lobby', code=lobbyCode)
        )

    except Exception as e:
        db.rollback()
        raise e

    finally:
        cursor.close()
        db.close()

@app.route('/admin')
@login_required
def admin():
    userid = session.get('userid')

    if not can_user(userid, 'site.admin'):
        flash('You do not have permission to access this page.', 'error')
        return redirect(request.referrer or abort(403))

    return render_template('admin/template.html')

if __name__ == "__main__":
    app.run(port=os.getenv("PORT"))