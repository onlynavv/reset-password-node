import express from "express"
import { MongoClient } from "mongodb";
import dotenv from "dotenv"
import cors from "cors"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { genPassword, createUser,getByUserName,getByUserId,updatePassword } from "./helper.js"
import nodemailer from "nodemailer"
import sendgridTransport from "nodemailer-sendgrid-transport"


dotenv.config()

const app = express()

const PORT = process.env.PORT;

app.use(cors())

app.use(express.json())

const MONGO_URL = process.env.MONGO_URL

async function createConnection(){
    const client = new MongoClient(MONGO_URL)
    await client.connect()
    console.log("mongodb connected")
    return client
}

export const client = await createConnection()

const transporter = nodemailer.createTransport(sendgridTransport({
    auth:{
        api_key:process.env.TRANSPORT_KEY
    }
}))

app.get("/", (request, response)=>{
    response.send("hai from reset password")
})

app.post("/register", async(request, response)=>{
    const {username, password, email} = request.body
    const userFromDB = await getByUserName(username)
    

    if(userFromDB){
        response.status(400).send({msg:"username already exists"})
        return
    }

    if(password.length < 8){
        response.status(400).send({msg: "password must be longer"})
        return
    }

    if(!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)){
		response.status(400).send({msg: "pattern does not match"})
		return
	}

    const hashedPassword = await genPassword(password)
    const result = await createUser({username, password:hashedPassword, email})
    response.send(result)
})

app.post("/login", async(request, response)=>{
    const {username, password} = request.body
    const userFromDB = await getByUserName(username)

    if(!userFromDB){
        response.status(401).send({msg:"incorrect credentials"})
        return
    }

    const storedPassword = userFromDB.password

    const isPasswordMatch = await bcrypt.compare(password, storedPassword)

    if(isPasswordMatch){
        const token = jwt.sign({id:userFromDB._id, username:username}, process.env.SECRET_KEY)
        response.send({msg:"successfull login",token:token, username:username})
    }else{
        response.status(401).send({msg: "incorrect credentials"})
    }
})

app.post("/forgot-password", async(request, response)=>{
    const {username} = request.body
    const userFromDB = await getByUserName(username)

    if(!userFromDB){
        response.status(401).send({msg:"user does not exist"})
        return
    }

    // token
    const secret = process.env.SECRET_KEY + userFromDB.password
    const token = jwt.sign({email:userFromDB.email, id:userFromDB._id, username:userFromDB.username},secret,{expiresIn: "15m"})
    

    const link = `https://reset-password-app-task.herokuapp.com/reset-password/${userFromDB._id}/${token}`
    

    transporter.sendMail({
        to:userFromDB.email,
        from: process.env.FROM_MAIL,
        subject:"password reset",
        html:`
            <h4>You have requested for the password reset</h4>
            <h4>click this <a href=${link}>link</a> to reset password</h4>

        `
    })

    response.send({msg:"password reset link has been sent to your email address"})
})

// verify the token
app.get("/reset-password/:id/:token", async(request, response, next)=>{
    const {id, token} = request.params
    const userFromDB = await getByUserId(id)
    

    if(!userFromDB){
        response.send({msg:"invalid credentials"})
        return
    }

    const secret = process.env.SECRET_KEY + userFromDB.password
    try{
        const result = jwt.verify(token, secret)
        response.redirect(`https://forgot-password-app-task.netlify.app/reset/${userFromDB._id}/${token}`)
    }catch(error){
        
        response.send(error.message)
    }
})

//
app.put("/reset-password/:id/:token", async(request, response, next)=>{
    const {id, token} = request.params
    const {password} = request.body
    const userFromDB = await getByUserId(id)
    
    if(!userFromDB){
        response.send({msg:"invalid credentials"})
        return
    }

    const secret = process.env.SECRET_KEY + userFromDB.password
    
    try{
        const result = jwt.verify(token, secret)
        if(password.length < 8){
            response.status(400).send({msg: "password must be longer"})
            return
        }

        if(!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)){
            response.status(400).send({msg: "pattern does not match"})
            return
        }

        const hashedPassword = await genPassword(password)
        const data  = await updatePassword(id,hashedPassword)
        response.send({msg:"password changed successfully, wait for 5 secs the page to redirect..."})
    }catch(error){
        
        response.send(error.message)
    }

})

app.listen(PORT, ()=>{
    console.log("app started at ", PORT)
})