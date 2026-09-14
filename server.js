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
    //check password strength


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

//statistics (total steps, avarage steő)

app.listen(port, ()=>{
    console.log(`Server is running on http://localhost:${port}`)
})