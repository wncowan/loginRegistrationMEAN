//Setup Mongoose
var mongoose = require("mongoose");
mongoose.connect('mongodb://localhost/basic_mongoose_login_registration')

//Setup app
var bcrypt = require("bcryptjs")
SALT_WORK_FACTOR = 10;
var express = require("express");
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");
var app = express();
app.use(session({
    secret: '...',
    resave: false,
    saveUninitialized: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "./static")));
app.use('/jquery', express.static(__dirname + '/node_modules/jquery/dist/'));
app.use('/bootstrap', express.static(__dirname + '/node_modules/bootstrap/dist/'));
app.set('views', path.join(__dirname, './views'));
app.set('view engine', 'ejs');

//create user model
var UserSchema = new mongoose.Schema({
    email: {
            type: String, 
            required: [true, "Email required."], 
            unique: [true, "Email already found in database."],
            validate: {
                validator: function(value) {
                    return /\S+@\S+\.\S+/.test(value);
                },
                message: "Email format invalid."
            }
        },
    first_name: {
        type: String, 
        required: [true, "First name required."],
        trim: true,
        validate: {
            validator: function(value) {
                return /^[a-zA-Z]+$/.test(value);
            },
            message: "First name may contain letters only."
        }
    },
    last_name: {
        type: String, 
        required: [true, "Last name required."],
        trim: true,
        validate: {
            validator: function(value) {
                return /^[a-zA-Z]+$/.test(value);
            },
            message: "First name may contain letters only."
        }
    },
    birthday: {
        type: Date, 
        required: [true, "Birthday required."],
        validate: {
            validator: function(value) {
                var now = new Date();
                now.setUTCHours(0,0,0,0);
                var then = new Date(value);
                return then < now;
            },
            message: "Birthday must be in the past."
        }
    },
    password: {
        type: String, 
        minlength: [8, "Password must be at least 8 characters."],
        required: [true, "Password required."],
        validate: {
            validator: function( value ) {
              return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]+/.test( value );
            },
            message: "Password failed validation, you must have at least 1 number, uppercase and special character"
          }
    },
}, {timestamps: true});
//Setup encryption
UserSchema.pre('save', function(next) {
    this.password = bcrypt.hashSync(this.password,10);
    next();
});
mongoose.model('User', UserSchema);
var User = mongoose.model('User');

//routes
app.get('/', function(req, res) {
    var errors = req.session.errors;
    req.session.errors = [];
    res.render("index", {errors:errors});
});

app.post('/login', function(req,res) {
    if (!(req.body.email && req.body.password)) {
        email = "";
        password = "";
    }
    var email = req.body.email;
    var password = req.body.password;
    User.findOne({email:email}, function(err,user) {
        req.session.errors = [];
        if(err) {
            req.session.errors.push("Problem with user credentials.")
        } else {
            if(user){
                //Check to see if user pwd matches entered.
                if(bcrypt.compareSync(password,user.password)){
                    req.session.user = user.email;
                    res.redirect('/success');
                }
                else {
                    req.session.errors.push("Problem with user credentials.")
                    res.redirect('/');
                }
            } else {
                req.session.errors.push("Problem with user credentials.")
                res.redirect('/');
            }
        }
    });
});

app.post('/register', function(req, res) {
    req.session.errors = [];
    var user = new User(req.body);
    //validate first to get all errors
    user.validate(function(err) {
        if(err) {
            for (var item in err.errors) {
                req.session.errors.push(err.errors[item].message);
            }
        }
    });
    //check that password and password conf ==
    if (req.body.password !== req.body.confirm_password) {
        req.session.errors.push("Password and confirmation do not match.");
    }
    //Finally, if there are no errors, save. (Doesn't work well because of async lag.)
    if (!req.session.errors.length) {
        user.save(function(err) {
            if(err){
                if(err.name=="BulkWriteError") {
                    req.session.errors.push("Duplicate email found in database.");
                } else {
                    console.log("Error!");
                }
            }
        });
    }
    //setTimeout(function(){res.redirect('/')},500); maybe not necessary??
    res.redirect('/');
});

app.get('/success', function(req,res) {
    if (req.session.user) {
        res.render('success');
    } else {
        res.redirect('/');
    }
});

//start server
var server = app.listen(8000, function() {
    console.log("listening on port 8000");
});