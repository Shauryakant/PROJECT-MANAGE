import { createServer } from 'http';
const port=3000;
const hostname='127.0.0.1';
const server=createServer((req,res)=>{
    if(req.url=='/') {
        res.statusCode=200;
        res.setHeader('Content-Type','text/plain');
        res.end('hey its empty')
    }
    else if(req.url=='/full') {
        res.statusCode=200;
        res.setHeader('Content-Type','text/plain');
        res.end('hey its full')
    }
    else {
        res.statusCode=404;
        res.setHeader('Content-Type','text/plain');
        res.end('File not found')
    }
})

server.listen(port,hostname,()=>{
    console.log(`SERVER IS LISTENING ON : http://${hostname}:${port}`);
    
})
