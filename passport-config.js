const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById){
    //fn to authenticate a user
    const authenticateUser = async (email, password, done)=>{
        //check if user exists
        const user = getUserByEmail(email)
        if(user == null){
            //call the done fn whenever authentication is complete
            return done(null, false, {message: 'No user with that email'})
        }
        try{
            //if user exists, verify the password
            if (await bcrypt.compare(password,user.password)){
                return done(null, user)
            } else{
                return done(null, false, {message: 'Password incorrect'})
            }

        }catch(e){
            return done(e)
        }
    }
    //find user by email and authenticate
    passport.use(new LocalStrategy({usernameField:'email'}, authenticateUser))
    //store the user credentials throughout the session
    passport.serializeUser((user, done)=> done(null , user.id))
    //remove the user credentials throughout the session after logout
    passport.deserializeUser((id, done)=>{
        return done(null, getUserById(id))
    })  

}

module.exports = initialize;