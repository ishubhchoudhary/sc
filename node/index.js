const express =  require('express');
const app = express();
const mysql  = require('mysql');
const bodyParser  = require('body-parser');

app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());
// app.use(express.json());

app.set('view engine', 'ejs');

const conn = mysql.createConnection({
	host:'localhost',
	user:'root',
	password:'',
	database:'crud'
});

conn.connect((err) => {
	if(err) throw err;
	console.log("connection successfully...");
});



app.get('/',(req, res) => {
	res.render('insert');
})

app.post('/insert',(req, res) => {

	let name = req.body.name;
	let email = req.body.email;
	let password = req.body.password;
	
	let sql = `INSERT INTO users (user_name, user_email, user_password) VALUES('${name}', '${email}', '${password}' )`;
	conn.query(sql,(err,result) => {
		if(err) throw err;
		res.redirect('/show');
		// res.end();
	});

})

app.get('/show',(req, res) => {

	let sql = `SELECT * FROM users`;
	conn.query(sql,(err,result) => {
		if(err) throw err;
		res.render('show',{users: result})
		// res.end();
	});

})

app.get('/edit/:id',(req, res) => {

	let id = req.params.id;
	
	let sql = `SELECT * FROM users WHERE user_id = ${id}`;
	conn.query(sql,(err,result) => {
		if(err) throw err;
		// console.log(result);
		res.render('edit',{users: result})
		// res.end();
	});

})

app.post('/update/:id',(req, res) => {

	let id = req.params.id;
	let name = req.body.name;
	let email = req.body.email;
	let password = req.body.password;
		console.log(name);
	
	let sql = `UPDATE users SET user_name='${name}',user_email='${email}', user_password='${password}'  WHERE user_id = ${id}`;
	conn.query(sql,(err,result) => {
		if(err) throw err;
		res.redirect('/show');
	});

	// res.end();
})

app.get('/delete/:id',(req, res) => {
	let id = req.params.id;
	let sql = `DELETE FROM users WHERE user_id = ${id}`;
	conn.query(sql,(err,result) => {
		if(err) throw err;
		res.redirect('/show');
	});
	// res.end();
})


let server = app.listen(5000,(err)=>{
	if(err) throw err;
	console.log("app running in 5000 port...");
})