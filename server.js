const express = require('express');
const mysql = require('mysql');

const app = express();
const port = 3000;
var pool = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: '',
    port:'3307',
    database: 'stepcounter'
});
app.use(express.urlencoded({extended: true}))
app.use(express.json());
app.get('/', (_req,res)=>{
    res.send(`Welcome to stepcounter API!`)
})
//USER ENDPOINTS -----------------

//registration
app.post('/users/register', (req, res)=> {
    const {name, email, passwd, confirm} = req.body;
    
    //check for missing fields
    if (!name || !email || !passwd || !confirm){
        return res.status(400).json({error:'Missing required fields'})
    }
    // check if passwords match
    if(passwd !== confirm){
        return res.status(400).json({error:'Passwords do not match'})
    }
    //TODO: check password strength


    //check if email already exists

    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'})
        }
        if (results.length > 0){
            return res.status(400).json({error: 'This email already exists'})
        }
        //insert new user into database
        pool.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, SHA1(?), "user")', [name, email, passwd], (error, results)=>{
            if (error){
                return res.status(500).json({error:'database injection error'})
            }
            res.status(201).json({message: 'user registered succesfully'})
        })
    })
    

})
//login
app.post('/users/login', (req, res)=>{
    const {email, passwd} = req.body;

    //VALIDATION    

    //check for missing fields
    if (!email || !passwd){
        return res.status(400).json({error: 'Missing fields'});
    }
    // check email and passwd exists
    pool.query('SELECT * FROM users WHERE email=? AND password=SHA1(?)',[email, passwd],(error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        //if there isn't a user with that passwd and email
        if (results.length == 0){
            return res.status(400).json({error:'Invalid credentials!'});
        }
        // if there is a user with that email and passwd
        
        //TODO:check if user is active
        if(results[0].is_active==0){
            return res.status(400).json({error: 'This account is banned by an admin!'})
        }
       
        const loggedUser= {
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        };

        pool.query('UPDATE users SET last_login=CURRENT_TIMESTAMP, login_count=login_count+1 WHERE ID=?', [results[0].ID], (error, resutls)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'});
        }
        //TODO: send logged user data to frontend
        res.status(200).json({message: 'You logged in succesfully!',loggedUser});
        })
        
        
    });
});
//logout

//password change

//get profile

//update profile

//delete profile
//STEPS ENDPOINTS ---------------------------

//create step

//get steps (user)

//update steps

//delete steps

//ADMIN ENDPOINTS ---------------------------

//get all users
app.get('/admin/users', (req,res)=>{
    pool.query('SELECT * FROM users', (error, results)=> {
        if (error){
            res.status(500).json({ 'Database query error: ': error});
        }
        else{
            res.status(200).json(results)
        }
    })
})

//deny user

//statistics (total steps, avarage step)

app.listen(port, ()=>{
    console.log(`Server is running on http://localhost:${port}`)
})