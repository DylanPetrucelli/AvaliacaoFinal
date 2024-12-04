import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use( express.json() );

const users = [];

const alunos = [
    
    {
        id: 1,
        nome: "Asdrubal",
        ra: "11111",
        nota1: 8.5,
        nota2: 9.5
    },
    {
        id: 2,
        nome: "Lupita",
        ra: "22222",
        nota1: 7.5,
        nota2: 7
    },
    {
        id: 3,
        nome: "Zoroastro",
        ra: "33333",
        nota1: 3,
        nota2: 4
    },
]

app.post('/register', async(req,res) => {

    const {username, password} = req.body;

    const hashedPassword = await bcrypt.hash(password,10);

    users.push( {username, password: hashedPassword} );
    console.log(users);

    res.status(201).json({"message": "user registered"});

});

app.post('/login', async(req,res) => {

    const {username, password} = req.body;

    const user = users.find( user => user.username === username );

    if ( !user || !( await bcrypt.compare(password, user.password) ) ) {

        return res.status(401).send('Login Incorreto!');
    }

    const token = jwt.sign(
        { username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
    );

    res.json(token);
    console.log('Login efetuado pelo usuário ' + user.username);

});

const authenticateJWT = (req, res, next) => {

    const authHeader = req.header('Authorization');
    console.log('Authorization: ' + authHeader);

    let token;
    
    if (authHeader) {
        const parts = authHeader.split(' ');
        if (parts.length === 2) {
            token = parts[1];
        }
    }
    
    if (!token) {
        return res.status(401).send('Acesso negado. Token não fornecido.');
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {

        if (err) {

            if (err.name === 'TokenExpiredError') {
                return res.status(401).send('Acesso negado. Token expirado.');

            } else if (err.name === 'JsonWebTokenError') {
                return res.status(403).send('Acesso negado. Token inválido.');

            } else {
                return res.status(403).send('Acesso negado. Erro na verificação do token.');
            }
        }

        req.user = user;

        const issuedAtISO = new Date(user.iat * 1000).toISOString();
        const expiresAtISO = new Date(user.exp * 1000).toISOString();

        console.log(`Token validado para usuário: ${user.username}
            Emitido em: ${issuedAtISO}
            Expira em: ${expiresAtISO}
        `);

        next();
    });

}

app.use(authenticateJWT);



app.get("/alunos", (req, res) => {

    res.status(200).json(alunos);
});

app.get("/alunos/medias", (req, res) => {
    if (alunos.lenght == 0) {
        return res.status(404).json({ message: "Nenhum aluno cadastrado." });
    }

    const medias = alunos.map(aluno => ({
        nome: aluno.nome,
        media: (aluno.nota1 + aluno.nota2) /2
    }));

    res.status(200).json(medias);
});

app.get("/alunos/aprovados", (req, res) => {
    if (alunos.lenght == 0) {
        return res.status(404).json({ message: "Nenhum aluno cadastrado." });
    }

    const resultado = alunos.map(aluno => ({
        nome: aluno.nome,
        resultado: (((aluno.nota1 + aluno.nota2) /2) >= 6) ? "aprovado" : "reprovado"
    }));

    res.status(200).json(resultado);
});

app.get("/alunos/:id", (req, res) => {
    const id = Number(req.params.id); 
    const index = alunos.findIndex(aluno => aluno.id === id);

    if (index === -1) {
        return res.status(404).json({ message: "Aluno nao encontrado" });
    }

    res.status(200).json(alunos[index]);
});

app.post("/alunos", authenticateJWT, (req, res) => {
    const { id, nome, ra, nota1, nota2 } = req.body;

    if (id == null || nome == null || ra == null || nota1 == null || nota2 == null) {
        return res.status(400).json({ message: "Dados incompletos. Verifique se inseriu os dados corretametne." });
    }
    
    const alunoExistente = alunos.find(aluno => aluno.id === id);
    if (alunoExistente) {
        return res.status(400).json({ message: "Esse id já está em uso." });
    }

    const novoAluno = {
        id,
        nome,
        ra,
        nota1: parseFloat(nota1),
        nota2: parseFloat(nota2)
    };

    alunos.push(novoAluno);

    res.status(201).json({ message: "Aluno adicionado com sucesso!",
        aluno: novoAluno
    });

});

app.put("/alunos/:id", authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { nome, ra, nota1, nota2 } = req.body;

    if (id == null || nome == null || ra == null || nota1 == null || nota2 == null) {
        return res.status(400).json({ message: "Dados incompletos. Verifique se inseriu os dados corretametne." });
    }

    const alunoIndex = alunos.findIndex(aluno => aluno.id == id);
    if (alunoIndex === -1) {
        return res.status(404).json({ message: "Aluno não encontrado." });
    }

    // Atualiza os dados do aluno
    alunos[alunoIndex] = {
        ...alunos[alunoIndex], // Mantém os dados anteriores
        nome, 
        ra,
        nota1: parseFloat(nota1),
        nota2: parseFloat(nota2)
    };

    // Retorna o aluno atualizado
    res.status(200).json({
        message: "Aluno atualizado com sucesso!",
        aluno: alunos[alunoIndex]
    });
});

app.delete("/alunos/:id", authenticateJWT, (req, res) => {
    const { id } = req.params; 
    const alunoIndex = alunos.findIndex(aluno => aluno.id == id);

    if (alunoIndex === -1) {
        return res.status(404).json({ message: "Aluno não encontrado." });
    }

    alunos.splice(alunoIndex, 1);

    res.status(200).json({
        message: "Aluno excluído com sucesso."
    });
});



app.listen(3000, () => {
    console.log("Server started!"); //fim :)
});