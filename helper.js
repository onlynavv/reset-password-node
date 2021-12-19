import { client } from "./index.js";
import bcrypt from "bcrypt"
import { ObjectId } from "mongodb";

async function getByUserName(username){
    return await client.db("resetpassword").collection("users").findOne({username:username})
}

async function getByUserId(id){
    return await client.db("resetpassword").collection("users").findOne({_id:ObjectId(id)})
}

async function genPassword(password){
    const NO_OF_ROUNDS = 10
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
    console.log(salt)
    const hashedPassword = await bcrypt.hash(password, salt)
    console.log(hashedPassword)
    return hashedPassword
}

async function createUser(data) {
    return await client.db("resetpassword").collection("users").insertOne(data);
}

async function updatePassword(id,password) {
    return await client.db("resetpassword").collection("users").updateOne({_id:ObjectId(id)},{$set:{password:password}});
}

export {getByUserName,genPassword,createUser,getByUserId,updatePassword}