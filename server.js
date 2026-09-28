const express = require('express');
var cors = require('cors');
const mysql = require('mysql');
var sha1 = require('sha1');

const app = express();
const port = 3000;
const pwdRegExp = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
var pool = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: '',
    port:'3307',
    database: 'stepcounter',
    timezone: 'Europe/Budapest'
});
app.use(cors()); //::::acces control allow origin
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
    //regExp -> reg|ular exp|ression
    if (!passwd.match(pwdRegExp)){
        return res.status(400).json({error:'Password is too weak!'})
    }


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
//logout ---- nem lesz ra backend endpoint

//password change
app.post('/users/:uid/passmod', (req, res)=>{
    const {oldpass, newpass, confirm} = req.body; //frontendből átvesszük az adatokat
    const uid = req.params.uid; // kiolvassuk az urlbol a user ID-t

    //megnezzuk hogy minden kotelezo mezot megadott e
    if (!oldpass || !newpass || !confirm){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    //osszehasonlitjuk az uj jelszavakat
    if (newpass != confirm){
        return res.status(400).json({error:'The new password and it\'s confirm does not match!'});
    }

    // megnezzuk hogy az uj megegyezik e a regivel
    if (oldpass == newpass){
        return res.status(400).json({error: 'The new password is the same as the old password!'})
    }
    //TODO: new password strength check with regular expression


    //megnezzuk hogy a megadott regi jelszo stimmel e
    pool.query('SELECT password FROM users WHERE ID=?', [uid], (error,results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        // ha nincs ilyen idju user
        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }
            //hasheljuk a megadott jelenlegi jelszot hogy ossze tudjuk hasonlitani az adatbazisban levovel
        const oldpassHash = sha1(oldpass);


        // ha nem stimmel a megadott regi jelszo
        if (results[0].password != oldpassHash){
            return res.status(400).json({error: 'The old password is not correct!'});
        }

        //update password

        pool.query('UPDATE users SET password=SHA1(?) WHERE ID=?', [newpass, uid], (error, results)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'});
            }
            if (!newpass.match(pwdRegExp)){
                return res.status(400).json({error:'Password is too weak!'})
            }

            return res.status(200).json({message: 'The password has been modified succesfully!'});
        });
    });
});

//get profile

app.get('/users/:uid', (req, res)=>{
    const uid = req.params.uid;

    if (!uid){
        return res.status(400).json({error: 'Missing user ID!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        // ha nincs ilyen idju user a tablaban
        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        let user = {
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role,
            created_at: results[0].created_at,
        }

        // ha van ilyen idju user
        return res.status(200).json({results: user});
    })
});
//update profile (username, email)
app.patch('/users/:uid', (req, res)=>{
    const uid = req.params.uid;
    const {username,email, luid } = req.body;

    if (!uid || !username || !email || !luid){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    if (uid != luid){
        return res.status(400).json({error: 'You are not authorized to update this profile!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }
        //ha ugyanazok az adatok mint az adatbazisban, akkor nem csinalunk semmit
        if (username == results[0].name && email == results[0].email){
            return res.status(400).json({error: 'No changes detected!'});
        }

        pool.query('SELECT * FROM users WHERE email=? AND ID!=?', [email, uid], (error, results2)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'});
            }

            if (results2.length > 0){
                return res.status(400).json({error: 'This email is already in use!'});
            }

            pool.query('UPDATE users SET name =?, updated_at = CURRENT_TIMESTAMP, email=? WHERE ID =?', [username, email, uid], (error, results3)=>{
                if (error){
                    return res.status(500).json({error: 'Database query error'});
                }
                return res.status(200).json({message: 'Profile updated succesfully!'});
            })
        })
    });

});
//delete profile

app.delete('/users/:uid', (req, res)=>{
    const uid = req.params.uid;
    const loggedUserID = req.body.luid; // a bejelentkezett user ID-ját a frontend küldi át

    if (!uid || !loggedUserID){
        return res.status(400).json({error: 'Missing user ID!'});
    }

    if (uid != loggedUserID){
        return res.status(400).json({error: 'You are not authorized to delete this profile!'});
    }

    pool.query('DELETE FROM users WHERE ID=?', [uid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.affectedRows == 1){
            return res.status(200).json({message: 'Profile deleted succesfully!'});
        }
        return res.status(200).json({message: 'No action occurred!'});

    })
});
//STEPS ENDPOINTS ---------------------------

//create step
app.post('/steps', (req, res)=>{
    const {steps, luid, date} = req.body;
    const today = new Date();

    if (!steps || !luid){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'})
        }

        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }
        if (new Date(date) > today){
            return res.status(400).json({error: 'You cannot add steps for a future date!'});
        }
        
        pool.query('SELECT * FROM steps WHERE user_id=? AND DATE(date)=?', [luid, date], (error, results)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'})
            }
            if (results.length > 0){
                return res.status(400).json({error: 'Step data for this date already exists!'});
            }
            if (steps < 0){
                return res.status(400).json({error: 'Step count cannot be negative!'});
            }
            pool.query('INSERT INTO steps (user_id, step_count, date) VALUES (?, ?, CURRENT_TIMESTAMP)', [luid, steps], (error, results)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'})
            }

            
            
            return res.status(201).json({message: 'Step data added succesfully!'});
        })
        })
        
    })
});
//get steps (user)
app.get('/steps/:uid', (req, res)=>{
    const uid = req.params.uid;
    const luid = req.body.luid;
    if (!uid){
        return res.status(400).json({error: 'Missing user ID!'});
    }
    if (uid != luid){
        return res.status(400).json({error: 'You are not authorized to view this user\'s steps!'});
    }

    pool.query('SELECT * FROM steps WHERE user_id=? ORDER BY date DESC', [uid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0){
            return res.status(200).json({message: 'No steps found for this user!'});
        }
        return res.status(200).json(results);
    })
})
//update steps
app.patch('/steps/:uid/:stepID', (req, res)=>{
    const luid = req.body.luid;
    const uid = req.params.uid;
    const stepID = req.params.stepID;

    if (!luid || !uid || !stepID){
        return res.status(400).json({error: 'Missing required fields!'});
    }
    if (uid !=luid){
        return res.status(400).json({error: 'You are not authorized to update this user\'s steps!'});
    }

    pool.query('SELECT * FROM steps WHERE ID=? AND user_id=?', [stepID, uid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0){
            return res.status(400).json({error: 'Step data with this ID doesn\'t exist for this user!'});
        }
        pool.query('UPDATE steps SET step_count=?, updated_at=CURRENT_TIMESTAMP WHERE ID=? AND user_id=?', [req.body.steps, stepID, uid], (error, results2)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'});
            }
            if (results2.affectedRows == 0){
                return res.status(400).json({error: 'Step data with this ID doesn\'t exist for this user!'});
            }
            return res.status(200).json({message: 'Step data updated succesfully!'});
        })
    })
})
//delete steps
app.delete('/steps/:stepID', (req, res) =>{
    const luid = req.body.luid;
    const stepID = req.params.stepID;

    if (!luid || !stepID){
        return res.status(400).json({error: 'Missing required fields!'});
    }
    if (luid != req.body.luid){
        return res.status(400).json({error: 'You are not authorized to delete this user\'s steps!'});
    }
    pool.query('DELETE FROM steps WHERE ID=? AND user_id=?', [stepID, luid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.affectedRows == 1){
            return res.status(200).json({message: 'Step data deleted succesfully!'});
        }
        return res.status(400).json({error: 'No action occured!'})

    })
})
//ADMIN ENDPOINTS ---------------------------

//get all users
app.post('/admin/users', (req,res)=>{
    const luid = req.body.luid;

    if (!luid){
        return res.status(400).json({error: 'Missing user ID!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results1)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        if (results1.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        if (results1[0].role != 'admin'){
            return res.status(400).json({error: 'You are not authorized to perform this action!'});
        }

        pool.query('SELECT * FROM users', (error, results)=> {
        if (error){
           return res.status(500).json({return: 'Database query error: '});
        }
        else{
            return res.status(200).json(results)
        }
    })
    });
})

//deny user
app.patch('/admin/status', (req,res)=>{
    const {uid, luid} = req.body;
    
    if (!uid || !luid){
        return res.status(400).json({error: 'Missing user ID!'});
    }
    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results)=>{
        if (error){
            return res.status(500).json({error: 'Database query error'});
        }

        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        if (results[0].role != 'admin'){
            return res.status(400).json({error: 'You are not authorized to perform this action!'});
        };
        pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
            if (error){
                return res.status(500).json({error: 'Database query error'});
            }

            if (results.length == 0){
                return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
            }

            pool.query('UPDATE users SET is_active = not is_active WHERE ID =?', [uid], (error, results2)=>{
                if (error){
                    return res.status(500).json({error: 'Database query error'});
            }

                return res.status(200).json({message: 'User status updated succesfully!'});
            })
        })
    })
});
    

//statistics (total steps, avarage step)

app.listen(port, ()=>{
    console.log(`Server is running on http://localhost:${port}`)
})