const express = require('express');
const router = require('express').Router();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
require('dotenv').config();
const db = require('./src/db.config');
const app = express();
const { cloudinary } = require('./utils/cloudinary');

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));
app.use(cors('*'));


// Verifies the generated token from the front-end [token stored in header request due to GET Request] to get the user id. example:
// {
//     status: "available",
//     price: 4429.99,
//     headers: {
//       "x-access-token": sessionStorage.getItem("apextoken")
//     }
// }
const verifyJWT = (req, res, next) => {
    const token = req.headers["x-access-token"];

    if (token) {
        jwt.verify(token, process.env.NODE_AUTH_SECRET, (err, decoded) => {
            if (err) {
                res.json({
                    status: "error",
                    message: "failed to authenticate",
                    auth: false
                });
            } else {
                req.userId = decoded.uid;
                next();
            }
        });
    } else {
        res.json({
            status: "error",
            message: "token was not received",
            auth: false
        })
    }
}

// Verifies the generated token from the front-end [token stored in body request due to POST request] to get the user id. example:
// {
//     status: "available",
//     price: 4429.99,
//     headers: {
//       "x-access-token": sessionStorage.getItem("apextoken")
//     }
// }
const verifyJWTbody = (req, res, next) => {
    const token = req.body.headers["x-access-token"];

    if (token) {
        jwt.verify(token, process.env.NODE_AUTH_SECRET, (err, decoded) => {
            if (err) {
                res.json({
                    status: "error",
                    message: "failed to authenticate",
                    auth: false
                });
            } else {
                req.userId = decoded.uid;
                next();
            }
        });
    } else {
        res.json({
            status: "error",
            message: "token was not received",
            auth: false
        })
    }
}



// user authentication/authorization code begins <-------------------------------------->
// endpoint for signing up a user
router.post('/auth/signup', async (req, res) => {
    try {
        // variables received from the front-end.
        const email = req.body.email;
        const firstname = req.body.firstname;
        const lastname = req.body.lastname;
        const password = req.body.password;
        const phone = req.body.phone;
        const address = req.body.address;
        const isadmin = req.body.isadmin;

        // generate encrypted password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        db.query(`SELECT first_name FROM users WHERE (email = ?)`, email, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to check for a unique email",
                    auth: false
                });
            } else {
                if (result.length == 0) {
                    db.query(`INSERT INTO users (email, first_name, last_name, password, phone, address, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [email, firstname, lastname, hashedPassword, phone, address, isadmin], (err, response) => {
                            if (err) {
                                res.json({
                                    status: "error",
                                    data: err,
                                    message: "an error occured while trying to insert data into the database",
                                    auth: false
                                })
                            } else {
                                const uid = response.insertId;
                                const token = jwt.sign({ uid }, process.env.NODE_AUTH_SECRET, {
                                    expiresIn: 1800,
                                });
                                res.json({
                                    status: "success",
                                    data: {
                                        token: token,
                                        id: response.insertId,
                                        first_name: firstname,
                                        last_name: lastname,
                                        email: email
                                    },
                                    message: "user account registered successfully",
                                    auth: true
                                });
                            }
                        });
                } else {
                    res.json({
                        status: "error",
                        message: 'user account already exists',
                        auth: false
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to sign up",
            auth: false
        });
    }
});



// endpoint for logging in a user
router.post('/auth/signin', (req, res) => {
    try {
        // variables received from the front-end.
        const email = req.body.email;
        const password = req.body.password;

        db.query(`SELECT id, first_name, last_name, email, password FROM users WHERE (email = ?)`, email, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while checking for the email in the database"
                });
            } else {
                if (result.length > 0) {
                    bcrypt.compare(password, result[0].password, (error, response) => {
                        if (error) {
                            res.json({
                                status: "error",
                                data: error,
                                message: "an error occured while checking the password",
                                auth: false
                            });
                        } else {
                            if (response) {
                                const uid = result[0].id;
                                const token = jwt.sign({ uid }, process.env.NODE_AUTH_SECRET, {
                                    expiresIn: 1800,
                                });
                                res.json({
                                    status: "success",
                                    data: {
                                        token: token,
                                        first_name: result[0].first_name,
                                        last_name: result[0].last_name,
                                        email: result[0].email
                                    },
                                    message: "logged in successfully",
                                    auth: true
                                });
                            } else {
                                res.json({
                                    status: "error",
                                    message: "password is incorrect",
                                    auth: false
                                });
                            }
                        }
                    });
                } else {
                    res.json({
                        status: "error",
                        message: "username does not exist",
                        auth: false
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to login",
            auth: false
        });
    }
});



// endpoint for changing a user password 
router.patch('/resetpassword', verifyJWTbody, (req, res) => {
    const id = req.userId;
    try {
        const password = req.body.password;
        const newpassword = req.body.newpassword;
        db.query(`SELECT password FROM users WHERE id=?`, id, (err, response) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "error trying to verify userID"
                });
            } else {
                bcrypt.compare(password, response[0].password, async (err, result) => {
                    if (err) {
                        res.json({
                            status: "error",
                            data: err,
                            message: "an error occured while checking the password"
                        });
                    } else {
                        if (result) {
                            const salt = await bcrypt.genSalt(10);
                            const hashedPassword = await bcrypt.hash(newpassword, salt);
                            try {
                                db.query(`UPDATE users SET password=? WHERE id=?`, [hashedPassword, id], (err, response) => {
                                    if (err) {
                                        res.json({
                                            status: "error",
                                            data: err,
                                            message: "an error occured while trying to update the password"
                                        });
                                    } else {
                                        if (response.affectedRows === 1) {
                                            res.json({
                                                status: "success",
                                                message: "password updated successfully"
                                            });
                                        } else {
                                            res.json({
                                                status: "error",
                                                message: "failed to update the password"
                                            });
                                        }
                                    }
                                });
                            } catch (error) {
                                res.json({
                                    status: "error",
                                    data: error,
                                    message: "error trying update password"
                                });
                            }
                        } else {
                            res.json({
                                status: "error",
                                message: "incorrect password"
                            });
                        }
                    }
                });
            }
        });
    } catch (error) {
        res.json({
            status: "error",
            data: error,
            message: "an error occured while trying to reset password"
        });
    }
});



// endpoint for deleting a user account (checks if the user has a property first)
router.delete('/deleteuser', verifyJWT, (req, res) => {
    // id is gotten from the middleware verifyJWT
    const id = req.userId;
    try {
        db.query(`SELECT id FROM property WHERE owner=?`, id, (err, response) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to check if user has any property from the database"
                });
            } else {
                if (response.length === 0) {
                    try {
                        // variables received from the front-end.
                        const email = req.headers["email"];
                        const password = req.headers["password"];

                        db.query(`SELECT password from users WHERE email =?`, email, (err, result) => {
                            if (err) {
                                res.json({
                                    status: "error",
                                    data: err,
                                    message: "an error occured while checking if the email exists"
                                });
                            } else {
                                if (result.length > 0) {
                                    bcrypt.compare(password, result[0].password, (err, response) => {
                                        if (err) {
                                            res.json({
                                                status: "error",
                                                data: err,
                                                message: "an error occured while checking the password"
                                            });
                                        } else {
                                            if (response) {
                                                db.query(`DELETE FROM users WHERE email=?`, email, (err, result) => {
                                                    if (err) {
                                                        res.json({
                                                            status: "error",
                                                            data: err,
                                                            message: "an error occured while trying to delete user"
                                                        });
                                                    } else {
                                                        res.json({
                                                            status: "success",
                                                            data: result,
                                                            message: "user account deleted successfully"
                                                        });
                                                    }
                                                });
                                            } else {
                                                res.json({
                                                    status: "error",
                                                    message: "password is incorrect"
                                                });
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    } catch (err) {
                        res.json({
                            status: "error",
                            data: err,
                            message: "an error occured while trying to delete user"
                        });
                    }
                } else {
                    res.json({
                        status: "error",
                        message: "cannot delete user with property(ies)"
                    });
                }
            }
        });
    } catch (error) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to check if user has any property"
        });
    }
});
// user authentication/authorization code ends <-------------------------------------->



// property advert code begins <-------------------------------------->
// endpoint for posting a property advert
router.post('/property', verifyJWTbody, (req, res) => {

    // variables received from the front-end. owner is gotten from the middleware verifyJWTbody
    const owner = req.userId;
    const status = req.body.status;
    const price = req.body.price;
    const state = req.body.state;
    const city = req.body.city;
    const address = req.body.address;
    const type = req.body.type;
    const imagedata = req.body.imagedata;
    try {
        db.query(`SELECT first_name FROM users WHERE id=?`, owner, async (error, response) => {
            if (error) {
                res.json({
                    status: "error",
                    data: error,
                    message: "an error occured while trying to fetch user data"
                });
            } else {
                if (response.length > 0) {
                    const username = response[0].first_name;
                    try {
                        await cloudinary.uploader.upload(imagedata, { folder: `apexhauz/${username}` }, (error, result) => {
                            if (error) {
                                res.json({
                                    status: "error",
                                    data: error,
                                    message: "an error occured while uploading image file to the server"
                                });
                            } else {
                                if (result) {
                                    try {
                                        const imageurl = result.url;

                                        db.query(`INSERT INTO property (owner, status, price, state, city, address, type, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [owner, status, price, state, city, address, type, imageurl], (err, response) => {
                                            if (err) {
                                                res.json({
                                                    status: "error",
                                                    data: err,
                                                    message: "an error occured while trying to insert property data into the database",
                                                });
                                            } else {
                                                if (response) {
                                                    const date = new Date;
                                                    const date_time = `${date.getFullYear()}-${date.getMonth() < 10 + 1 ? "0" + (date.getMonth() + 1) : date.getMonth() + 1}-${date.getDate() < 10 ? "0" + date.getDate() : date.getDate()}T${date.getHours() < 10 ? "0" + date.getHours() : date.getHours()}:${date.getMinutes() < 10 ? "0" + date.getMinutes() : date.getMinutes()}:${date.getSeconds() < 10 ? "0" + date.getSeconds() : date.getSeconds()}.000Z`;

                                                    res.json({
                                                        status: "success",
                                                        data: {
                                                            id: response.insertId,
                                                            status: status,
                                                            type: type,
                                                            state: state,
                                                            city: city,
                                                            address: address,
                                                            price: price,
                                                            created_on: date_time,
                                                            image_url: imageurl,
                                                            image_public_id: result.public_id
                                                        },
                                                        message: "property added successfully",
                                                    });
                                                } else {
                                                    res.json({
                                                        status: "error",
                                                        message: "no response received from the server"
                                                    });
                                                }
                                            }
                                        });
                                    } catch (err) {
                                        res.json({
                                            status: "error",
                                            data: err,
                                            message: "an error occured while trying to post property",
                                        });
                                    }
                                } else {
                                    res.json({
                                        status: "error",
                                        message: "no response received from the server"
                                    });
                                }
                            }
                        });
                    } catch (err) {
                        res.json({
                            status: "error",
                            data: err,
                            message: "an error occured while trying to upload this document to the server"
                        })
                    }
                } else {
                    res.json({
                        status: "error",
                        message: `user with id: ${owner} does not exist in the database`,
                    });
                }
            }
        });
    } catch (error) {
        res.json({
            status: "error",
            data: error,
            message: "an error occured while trying to validate user id"
        });
    }
});



// endpoint for updating a property using id
router.patch('/property/:id', verifyJWTbody, (req, res) => {
    try {
        // variables received from the front-end. owner is gotten from the middleware verifyJWTbody
        const id = req.params.id;
        const owner = req.userId;
        const status = req.body.status;
        const price = req.body.price;
        const state = req.body.state;
        const city = req.body.city;
        const address = req.body.address;
        const type = req.body.type;
        const imagedata = req.body.imagedata;

        db.query(`SELECT owner FROM property WHERE id=?`, id, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to verify userID from the database",
                });
            } else {
                if (owner === result[0].owner) {
                    try {
                        db.query(`SELECT first_name FROM users WHERE id=?`, owner, async (err, response) => {
                            if (err) {
                                res.json({
                                    status: "error",
                                    data: err,
                                    message: "an error occured while trying fetch user data from the database",
                                });
                            } else {
                                if (response) {
                                    const username = response[0].first_name;
                                    try {
                                        await cloudinary.uploader.upload(imagedata, { folder: `apexhauz/${username}` }, (error, result) => {
                                            if (error) {
                                                res.json({
                                                    status: "error",
                                                    data: error,
                                                    message: "an error occured while uploading image file to the server"
                                                });
                                            } else {
                                                if (result) {
                                                    const imageurl = result.url;
                                                    console.log(imageurl)

                                                    db.query(`UPDATE property SET status=?, price=?, city=?, address=?, type=?, image_url=?, state=? WHERE id=?`, [status, price, city, address, type, imageurl, state, id], (err, response) => {
                                                        if (err) {
                                                            res.json({
                                                                status: "error",
                                                                data: err,
                                                                message: "an error occured while trying to update property data",
                                                            });
                                                        } else {
                                                            if (response) {
                                                                const date = new Date;
                                                                const date_time = `${date.getFullYear()}-${date.getMonth() < 10 + 1 ? "0" + (date.getMonth() + 1) : date.getMonth() + 1}-${date.getDate() < 10 ? "0" + date.getDate() : date.getDate()}T${date.getHours() < 10 ? "0" + date.getHours() : date.getHours()}:${date.getMinutes() < 10 ? "0" + date.getMinutes() : date.getMinutes()}:${date.getSeconds() < 10 ? "0" + date.getSeconds() : date.getSeconds()}.000Z`;

                                                                res.json({
                                                                    status: "success",
                                                                    data: {
                                                                        id: id,
                                                                        status: status,
                                                                        type: type,
                                                                        state: state,
                                                                        city: city,
                                                                        address: address,
                                                                        price: price,
                                                                        created_on: date_time,
                                                                        image_url: imageurl
                                                                    },
                                                                    message: "property updated successfully",
                                                                    additionalInfo: response.affectedRows + " row updated"
                                                                });
                                                            } else {
                                                                res.json({
                                                                    status: "error",
                                                                    message: "no response received from the server, try again"
                                                                });
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    res.json({
                                                        status: "error",
                                                        message: "no response received from the server"
                                                    });
                                                }
                                            }
                                        });
                                    } catch (error) {
                                        res.json({
                                            status: "error",
                                            data: error,
                                            message: "an error occured while trying to upload data to the database",
                                        });
                                    }
                                } else {
                                    res.json({
                                        status: "error",
                                        message: "user does not exist in the database"
                                    });
                                }
                            }
                        });
                    } catch (error) {
                        res.json({
                            status: "error",
                            data: error,
                            message: "an error occured while trying fetch user data from the database",
                        });
                    }
                } else {
                    res.json({
                        status: "error",
                        message: "property is not owned by user",
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to update property",
        });
    }
});



// endpoint for reporting a property as fraudulent
router.post('/property/:id/report', verifyJWTbody, (req, res) => {
    try {
        // variables received from the front-end. owner is gotten from the middleware verifyJWTbody
        const pid = req.params.id;
        const reason = req.body.reason;
        const description = req.body.description;

        db.query(`INSERT INTO reports (property_id, reason, description) VALUES (?, ?, ?)`,
            [pid, reason, description], (err, response) => {
                if (err) {
                    res.json({
                        status: "error",
                        data: err,
                        message: "an error occured while trying to insert report into the database",
                    })
                } else {
                    const date = new Date;
                    const date_time = `${date.getFullYear()}-${date.getMonth() < 10 + 1 ? "0" + (date.getMonth() + 1) : date.getMonth() + 1}-${date.getDate() < 10 ? "0" + date.getDate() : date.getDate()}T${date.getHours() < 10 ? "0" + date.getHours() : date.getHours()}:${date.getMinutes() < 10 ? "0" + date.getMinutes() : date.getMinutes()}:${date.getSeconds() < 10 ? "0" + date.getSeconds() : date.getSeconds()}.000Z`;

                    res.json({
                        status: "success",
                        data: {
                            id: response.insertId,
                            property_id: pid,
                            reason: reason,
                            description: description,
                            created_on: date_time,
                        },
                        message: "report added successfully",
                    });
                }
            });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: `an error occured while trying to report property`,
        });
    }
});



// endpoint for marking a property as sold
router.patch('/property/:id/sold', verifyJWTbody, (req, res) => {
    try {
        // variables received from the front-end. owner is gotten from the middleware verifyJWTbody
        const id = req.params.id;
        const owner = req.userId;

        const status = req.body.status;

        db.query(`SELECT * FROM property WHERE id=?`, id, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to verify userID from the database",
                });
            } else {
                if (owner === result[0].owner) {
                    try {
                        db.query(`UPDATE property SET status=? WHERE id=?`, [status, id], (err, response) => {
                            if (err) {
                                res.json({
                                    status: "error",
                                    data: err,
                                    message: "an error occured while trying to update property data to sold",
                                });
                            } else {
                                res.json({
                                    status: "success",
                                    data: {
                                        id: id,
                                        status: status,
                                        type: result[0].type,
                                        state: result[0].state,
                                        city: result[0].city,
                                        address: result[0].address,
                                        price: result[0].price,
                                        created_on: result[0].created_on,
                                        image_url: result[0].image_url
                                    },
                                    message: "property set to sold successfully",
                                    additionalInfo: response.affectedRows + " row updated"
                                });
                            }
                        });
                    } catch (error) {
                        res.json({
                            status: "error",
                            data: err,
                            message: "an error occured while trying to update property to sold",
                        });
                    }
                } else {
                    res.json({
                        status: "error",
                        message: "an error occured while trying to verify user of this property",
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to update property",
        });
    }
});



// endpoint for deleting a property
router.delete('/property/:id', verifyJWT, (req, res) => {
    try {
        // variables received from the front-end. owner is gotten from the middleware verifyJWT
        const id = req.params.id;
        const owner = req.userId;

        db.query(`SELECT * FROM property WHERE id=?`, id, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to verify userID from the database",
                });
            } else {
                if (owner === result[0].owner) {
                    try {
                        db.query(`DELETE FROM property WHERE id=?`, id, (err, response) => {
                            if (err) {
                                res.json({
                                    status: "error",
                                    data: err,
                                    message: "an error occured while trying to delete property",
                                });
                            } else {
                                res.json({
                                    status: "success",
                                    data: {
                                        id: id,
                                        status: result[0].status,
                                        type: result[0].type,
                                        state: result[0].state,
                                        city: result[0].city,
                                        address: result[0].address,
                                        price: result[0].price,
                                        created_on: result[0].created_on,
                                        image_url: result[0].image_url
                                    },
                                    message: "property deleted successfully",
                                    additionalInfo: response.affectedRows + " row updated"
                                });
                            }
                        });
                    } catch (error) {
                        res.json({
                            status: "error",
                            data: err,
                            message: "an error occured while trying to delete property",
                        });
                    }
                } else {
                    res.json({
                        status: "error",
                        message: "an error occured while trying to verify user of this property",
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: "an error occured while trying to delete property",
        });
    }
});



// endpoint for searching for a property by type
router.get('/property/search', verifyJWT, (req, res) => {
    // variables received from the front-end.
    const type = req.query.type;
    try {
        db.query(`SELECT * FROM property WHERE type=?`, type, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: `an error occured while trying to fetch property(ies) with type: ${type} from the database`,
                });
            } else {
                if (result.length > 0) {
                    res.json({
                        status: "success",
                        data: [
                            ...result
                        ],
                        message: "property request successfully"
                    });
                } else {
                    res.json({
                        status: "error",
                        message: `property(ies) with type: ${type} does not exist in the database`,
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: `an error occured while trying to fetch property(ies) with type: ${type}`,
        });
    }
});



// endpoint for fetching a property with a particular id
router.get('/property/:id', (req, res) => {
    // variables received from the front-end.
    const id = req.params.id;
    try {
        db.query(`SELECT * FROM property WHERE id=?`, id, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to verify property id from the database",
                });
            } else {
                if (result.length > 0) {
                    res.json({
                        status: "success",
                        data: {
                            id: id,
                            status: result[0].status,
                            type: result[0].type,
                            state: result[0].state,
                            city: result[0].city,
                            address: result[0].address,
                            price: result[0].price,
                            created_on: result[0].created_on,
                            image_url: result[0].image_url
                        },
                        message: "property request successfully"
                    });
                } else {
                    res.json({
                        status: "error",
                        message: `property with id: ${id} does not exist in the database`,
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: `an error occured while trying to get property with id: ${id}`,
        });
    }
});



// endpoint for fetching all the properties in the database
router.get('/property', verifyJWT, (req, res) => {
    try {
        db.query(`SELECT * FROM property`, (err, result) => {
            if (err) {
                res.json({
                    status: "error",
                    data: err,
                    message: "an error occured while trying to get all properties data from the database",
                });
            } else {
                if (result.length > 0) {
                    res.json({
                        status: "success",
                        data: [
                            ...result
                        ],
                        message: "property request successfully"
                    });
                } else {
                    res.json({
                        status: "error",
                        message: `there are no properties in the database`,
                    });
                }
            }
        });
    } catch (err) {
        res.json({
            status: "error",
            data: err,
            message: `an error occured while trying to get all properties`,
        });
    }
});
// property advert code ends <-------------------------------------->



app.use('/api/v1', router);

const PORT = process.env.NODE_PORT || 3000;
app.listen(PORT, () => {
    console.log(`Node Server is online at port ${PORT}!!!`);
});