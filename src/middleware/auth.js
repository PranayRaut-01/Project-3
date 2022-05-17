const jwt = require("jsonwebtoken");
const  mongoose = require("mongoose");

const bookModel = require("../models/BooksModel");
const userModel = require("../models/userModel");

///////////////// [ ALL AUTHENTICATION LOGIC HERE ] /////////////////
const authenticUser = function (req, res, next) {
  try {

   const token = req.headers["x-api-key"];
    if (!token) {
      return res.status(404).send({ status: false, message: "Token must be present" });
    }

    jwt.verify(token, "Books Management", function (error, decodedToken) { 
      if (error) {
        return res.status(401).send({ status: false, message: "token invalid" });
      }
      req.userId= decodedToken.userId
      next();
    });

  } 
  catch (err) {
    res.status(500).send({ status: false, message: err.message });
  }
};


///////////////// [ ALL AUTHORISATION LOGIC HERE ] /////////////////
const authorizedUser = async function (req, res, next) {
  try {

    const bookId = req.params.bookId;
    if (bookId) {
      if (!mongoose.Types.ObjectId.isValid(bookId)) {
        return res.status(400).send({ status: false, message: "Provide valid bookId" });
      }

      const findBook = await bookModel.findOne({_id:bookId,isDeleted:false});
      if (!findBook)
      return res.status(404).send({ status: false, message: "No book with this Id" });

      const findUserId = findBook.userId;
      const userLoggedIn = req.userId;
      if (findUserId != userLoggedIn) {
        return res.status(403).send({status: false,message: "You are not authorised for this request"});
      } 
      else {
        return next();
      }
    }
    const data = req.body;
    if (Object.keys(data).length == 0)
      return res
        .status(400)
        .send({ status: false, message: "Please provide valid request body" });

    const userId = data.userId
    if (!userId)
      return res
        .status(400)
        .send({ status: false, message: "please provide userId" });
  
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).send({ status: false, message: "Provide valid authorId" });
      }
      const validUserId = await userModel.findOne({
        _id: userId,
        isDeleted: false,
      });
      if (!validUserId)
        return res
          .status(404)
          .send({ status: false, message: "No User With Giver Id Found." });
          
      const userLoggedIn = req.userId;
      if (userId != userLoggedIn) {
        return res.status(403).send({status: false,message: "You are not authorised for this request"});
      } 
      else {
       return next();
      }

    
} 
catch (err) {
  res.status(500).send({ status: false, message: err.message });
}
};


///////////////// [ EXPRORTED MIDDLEWARE ] /////////////////
module.exports.authenticUser = authenticUser;
module.exports.authorizedUser = authorizedUser;
