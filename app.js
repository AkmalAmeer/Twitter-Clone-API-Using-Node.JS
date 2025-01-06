const express = require('express')
const {open} = require('sqlite')
const path = require('path')
const sqlite3 = require('sqlite3')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()
app.use(express.json())

const jwtSecret = 'my_jwt_secret'
const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server started at http://localhost:3000/')
    })
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}
initializeDbAndServer()

const getFollowingPeopleID = async username => {
  const getFollowqry = `
        SELECT 
            following_user_id FROM follower f
        INNER JOIN user u ON u.user_id = f.follower_user_id
        WHERE u.username = ?
    `
  const follow = await db.all(getFollowqry, [username])
  const listOfIds = follow.map(eachUser => eachUser.following_user_id)
  return listOfIds
}

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']
  if (token) {
    const jwtToken = token.split(' ')[1]
    jwt.verify(jwtToken, jwtSecret, (err, payload) => {
      if (err) {
        return res.status(401).send('Invalid JWT Token')
      } else {
        req.username = payload.username
        req.userId = payload.userId
        next()
      }
    })
  } else {
    return res.status(401).send('Invalid JWT Token')
  }
}

// Middleware to verify tweet access
const tweetVerify = async (req, res, next) => {
  const {userId} = req
  const {tweetId} = req.params
  const getTweetQry = `
        SELECT 1
        FROM tweet t
        INNER JOIN follower f ON f.following_user_id = t.user_id
        WHERE t.tweet_id = ? AND f.follower_user_id = ?
    `
  const tweet = await db.get(getTweetQry, [tweetId, userId])
  if (!tweet) {
    return res.status(401).send('Invalid Request')
  }
  next()
}

// API 1: Register a new user
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body
  const getusrqry = `SELECT * FROM user WHERE username = ?`
  const userDBDetails = await db.get(getusrqry, [username])

  if (userDBDetails !== undefined) {
    res.status(400).send('User already exists')
  } else {
    if (password.length < 6) {
      return res.status(400).send('Password is too short')
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const createUsrqry = `INSERT INTO user (username, password, name, gender) VALUES (?, ?, ?, ?)`
    await db.run(createUsrqry, [username, hashedPassword, name, gender])
    res.send('User created successfully')
  }
})

// API 2: User login
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const getusrqry = `SELECT * FROM user WHERE username = ?`
  const userDBDetails = await db.get(getusrqry, [username])
  if (userDBDetails !== undefined) {
    const isPwdCorrect = await bcrypt.compare(password, userDBDetails.password)
    if (isPwdCorrect) {
      const payload = {username, userId: userDBDetails.user_id}
      const jwtToken = jwt.sign(payload, jwtSecret)
      res.send({jwtToken})
    } else {
      res.status(400).send('Invalid password')
    }
  } else {
    res.status(400).send('Invalid user')
  }
})

// API 3: Get latest tweets from people the user follows
app.get('/user/tweets/feed/', authenticateToken, async (req, res) => {
  const {username} = req
  const followingPeopleId = await getFollowingPeopleID(username)

  const query = `
        SELECT username, tweet, date_time as dateTime
        FROM user u
        INNER JOIN tweet t ON t.user_id = u.user_id
        WHERE u.user_id IN (${followingPeopleId.map(() => '?').join(',')})
        ORDER BY date_time DESC
        LIMIT 4
    `

  const tweets = await db.all(query, followingPeopleId)
  res.send(tweets)
})

// API 4: Get the list of people the user follows
app.get('/user/following/', authenticateToken, async (req, res) => {
  const {userId} = req
  const query = `
        SELECT u.name
        FROM follower f
        INNER JOIN user u ON u.user_id = f.following_user_id
        WHERE f.follower_user_id = ?
    `
  const followingPeople = await db.all(query, [userId])
  res.send(followingPeople)
})

// API 5: Get the list of followers of the user
app.get('/user/followers/', authenticateToken, async (req, res) => {
  const {userId} = req
  const query = `
        SELECT u.name
        FROM follower f
        INNER JOIN user u ON u.user_id = f.follower_user_id
        WHERE f.following_user_id = ?
    `
  const followers = await db.all(query, [userId])
  res.send(followers)
})

// API 6: Get tweet details
app.get(
  '/tweets/:tweetId/',
  authenticateToken,
  tweetVerify,
  async (req, res) => {
    const {tweetId} = req.params
    const query = `
        SELECT t.tweet, t.date_time AS dateTime,
               (SELECT COUNT(*) FROM 'like' WHERE tweet_id = ?) AS likes,
               (SELECT COUNT(*) FROM reply WHERE tweet_id = ?) AS replies
        FROM tweet t
        WHERE t.tweet_id = ?
    `
    const tweet = await db.get(query, [tweetId, tweetId, tweetId])
    if (tweet) {
      res.send(tweet)
    } else {
      res.status(404).send('Tweet not found')
    }
  },
)

// API 7: Get the list of users who liked the tweet
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  tweetVerify,
  async (req, res) => {
    const {tweetId} = req.params
    const query = `
        SELECT u.username 
        FROM 'like' l
        INNER JOIN user u ON l.user_id = u.user_id
        WHERE l.tweet_id = ?
    `
    const likedUsers = await db.all(query, [tweetId])
    const listOfUsers = likedUsers.map(user => user.username)
    res.send({likes: listOfUsers})
  },
)

// API 8: Get the list of replies for a tweet
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  tweetVerify, // Ensures the tweet is from a followed user
  async (req, res) => {
    const { tweetId } = req.params;

    try {
      // Fetch the list of replies
      const repliesQuery = `
          SELECT u.name, r.reply
          FROM reply r
          INNER JOIN user u ON r.user_id = u.user_id
          WHERE r.tweet_id = ?
      `;
      const replies = await db.all(repliesQuery, [tweetId]);

      // Send the response with the list of replies
      res.send({
        replies: replies.map(reply => ({
          name: reply.name,
          reply: reply.reply,
        })),
      });
    } catch (error) {
      console.error(`Error fetching replies for tweetId ${tweetId}:`, error.message);
      res.status(500).send('Internal Server Error');
    }
  }
);


// API 9: Get all tweets of the user
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  const {userId} = req
  const query = `
        SELECT t.tweet, t.date_time AS dateTime,
               COUNT(DISTINCT l.like_id) AS likes,
               COUNT(DISTINCT r.reply_id) AS replies
        FROM tweet t
        LEFT JOIN reply r ON t.tweet_id = r.tweet_id
        LEFT JOIN 'like' l ON t.tweet_id = l.tweet_id
        WHERE t.user_id = ?
        GROUP BY t.tweet_id
    `
  const tweets = await db.all(query, [userId])
  res.send(tweets)
})

// API 10: Create a new tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  const {tweet} = req.body
  const {userId} = req
  const dateTime = new Date().toISOString().slice(0, 19).replace('T', ' ')
  const query = `
        INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, ?)
    `
  await db.run(query, [tweet, userId, dateTime])
  res.send('Created a Tweet')
})

// API 11: Delete a tweet
app.delete('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params
  const {userId} = req
  const query = `
        SELECT *
        FROM tweet 
        WHERE user_id = ? AND tweet_id = ?
    `
  const tweet = await db.get(query, [userId, tweetId])
  if (tweet === undefined) {
    res.status(401).send('Invalid Request')
  } else {
    const deleteQuery = `
            DELETE FROM tweet 
            WHERE tweet_id = ?
        `
    await db.run(deleteQuery, [tweetId])
    res.send('Tweet Removed')
  }
})

module.exports = app
