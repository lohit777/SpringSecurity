console.log('Hello World!');
let name = 'Lohit';
console.log(name) ;
const interestRate = 0.3;
console.log(interestRate) ;
name = 1;
console.log(name);
//We can change the type of a variable in runtime in js
console.log(typeof name);
let val = null ;
console.log(typeof val);
//in this case type of val will be object
let person={
    name:'Lohit',
    age:25// this is a property of the object
};// This is an object
console.log(person);

person.name = 'Bala' ;
console.log(person) ;

person['name'] = 'Lohith';
console.log(person);
//In this 2 ways we can change value of a property in a object

let selection = 'age';
person[selection] = 26;
console.log(person) ;
//We cant assign property to a var in dot notation

let selectedColors = ['red','green'];
selectedColors[2]=5;
console.log(selectedColors);

function greet(name) // here it is called parameter
{
    console.log('Hello  '  + name);
}

greet('Lohit') ; //this is called argument

function square(number){
    return number*number ;
}

let number =  square(2) ;
console.log(number) ;