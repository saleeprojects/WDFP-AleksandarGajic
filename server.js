const express = require("express");
const { engine } = require("express-handlebars");
const sqlite3 = require("sqlite3");
const session = require("express-session");
const connectSqlite3 = require("connect-sqlite3");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const port = 3000;
const app = express();

const adminLogin = "aleksandar";
const adminPassword = "123";

// -------DATABASE---------
const dbFile = "ag-database.db";
const db = new sqlite3.Database(dbFile);

// -------- HANDLEBARS ------------
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./views");

// -------- MIDDLEWARES ------------
// defines a middleware to log all the incoming requests' URL
app.use((req, res, next) => {
  console.log("Req. URL: ", req.url);
  next();
});
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//--------------CREATE Table user ------------------

db.run(
  "CREATE TABLE IF NOT EXISTS user (userID INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL, role INTEGER)",
  (error) => {
    if (error) {
      console.log("Error: ", error);
    } else {
      console.log("----> Table user created!");
    }
  }
);

//----------------------------------------CREATE Table education and inserting values ----------------------------------------
db.run(
  "CREATE TABLE IF NOT EXISTS education (educationID INTEGER PRIMARY KEY AUTOINCREMENT, userID INTEGER REFERENCES user(userID) ON DELETE CASCADE ON UPDATE CASCADE, school TEXT NOT NULL, degree TEXT NOT NULL, degreeDescription TEXT, date DATE)",
  (error) => {
    if (error) {
      console.log("Error: ", error);
    } else {
      console.log("----> Table education created!");

      //Flag to prevent duplicate insertions
      let insertedEducation = false;

      // Check if education data has been inserted before
      db.get("SELECT 1 FROM education LIMIT 1", (selectError, row) => {
        if (!selectError && row) {
          insertedEducation = true;
        }

        // Insert education data if it hasn't been inserted before
        if (!insertedEducation) {
          const education = [
            {
              userID: 1,
              school: "Boston High School",
              degree: "High School Diploma in STEM",
              degreeDescription:
                "Focused on science, technology, engineering, and mathematics with an emphasis on critical thinking and innovation.",
              date: "2012-2016",
            },
            {
              userID: 1,
              school: "University of California, Berkeley",
              degree: "Bachelor's Degree in Computer Science",
              degreeDescription:
                "Covers core computer science topics such as algorithms, artificial intelligence, software engineering, and database systems, providing a robust foundation for the tech industry.",
              date: "2016-2020",
            },
            {
              userID: 1,
              school: "Massachusetts Institute of Technology (MIT)",
              degree: "Master's Degree in Artificial Intelligence",
              degreeDescription:
                "Focuses on advanced topics in artificial intelligence, including machine learning, neural networks, natural language processing, and robotics.",
              date: "2020-2022",
            },
            {
              userID: 1,
              school: "Stanford University",
              degree: "PhD in Computer Science",
              degreeDescription:
                "Research focuses on distributed systems and their applications in cloud computing, blockchain, and large-scale data processing.",
              date: "2022-Present",
            },
            {
              userID: 1,
              school: "New York University (NYU)",
              degree:
                "Bachelor of Science in Software Engineering with Specialization in Mobile App Development",
              degreeDescription:
                "Hands-on program emphasizing software engineering principles, mobile app design, and development. Includes courses on iOS and Android development, cloud computing, and web technologies.",
              date: "2023-2025",
            },
          ];

          education.forEach((eduData) => {
            db.run(
              "INSERT INTO education (userID, school, degree, degreeDescription, date) VALUES (?, ?, ?, ?, ?)",
              [
                eduData.userID,
                eduData.school,
                eduData.degree,
                eduData.degreeDescription,
                eduData.date,
              ],
              (error) => {
                if (error) {
                  console.log("Error: ", error);
                } else {
                  console.log("Line added into education table!");
                }
              }
            );
          });
        }
      });
    }
  }
);

//----------------------------------------CREATE Table Projects and inserting values ----------------------------------------
db.run(
  "CREATE TABLE IF NOT EXISTS projects (projectID INTEGER PRIMARY KEY AUTOINCREMENT, userID INTEGER REFERENCES user(userID) ON DELETE CASCADE ON UPDATE CASCADE, projectTitle TEXT NOT NULL, projectDescription TEXT, projectYear TEXT)",
  (error) => {
    if (error) {
      console.log("Error: ", error);
    } else {
      console.log("----> Table projects created!");

      // Flag used to prevent duplicate insertions
      let insertedProjects = false;

      // Check if projects data has been inserted before
      db.get("SELECT 1 FROM projects LIMIT 1", (selectError, row) => {
        if (!selectError && row) {
          insertedProjects = true;
        }

        // Insert projects data if it hasn't been inserted before
        if (!insertedProjects) {
          const projects = [
            {
              projectID: 1,
              userID: 1,
              projectTitle: "TravelBuddy: Personalized Trip Planner",
              projectDescription:
                "An AI-powered travel planning platform that generates personalized itineraries based on user preferences. Developed with Python (Flask) for the backend and Vue.js for the frontend, the platform integrates APIs for booking flights, hotels, and activities.",
              projectYear: "2023",
            },
            {
              projectID: 2,
              userID: 1,
              projectTitle: "EcoSnap: Sustainable Shopping Companion",
              projectDescription:
                "A mobile app built using Flutter that helps users make eco-friendly shopping choices by scanning product barcodes. The app provides sustainability ratings and alternative recommendations, backed by a custom API and a MongoDB database.",
              projectYear: "2022",
            },
            {
              projectID: 3,
              userID: 1,
              projectTitle: "GameForge: Indie Game Builder",
              projectDescription:
                "A desktop application for aspiring game developers, built with C++ and Unreal Engine. The tool simplifies game design with drag-and-drop mechanics, pre-built templates, and real-time performance analysis.",
              projectYear: "2021",
            },
            {
              projectID: 4,
              userID: 1,
              projectTitle: "CodeConnect: Developer Collaboration Platform",
              projectDescription:
                "A platform designed for developers to collaborate on coding projects in real time. Built using MERN stack (MongoDB, Express.js, React, Node.js), the tool includes features such as live code editing, version control, and a project management dashboard.",
              projectYear: "2023",
            },
            {
              projectID: 5,
              userID: 1,
              projectTitle: "HealthSync: Fitness and Nutrition Tracker",
              projectDescription:
                "A cross-platform mobile app developed in Kotlin (Android) and Swift (iOS) that helps users track fitness activities and manage their diet. Features include integration with wearable devices, personalized health insights, and a meal planner.",
              projectYear: "2022",
            },
          ];

          projects.forEach((projectData) => {
            db.run(
              "INSERT INTO projects (projectID, userID, projectTitle, projectDescription, projectYear) VALUES (?, ?, ?, ?, ?)",
              [
                projectData.projectID,
                projectData.userID,
                projectData.projectTitle,
                projectData.projectDescription,
                projectData.projectYear,
              ],
              (error) => {
                if (error) {
                  console.log("Error: ", error);
                } else {
                  console.log("Line added into projects table!");
                }
              }
            );
          });
        }
      });
    }
  }
);

//Use of a GET CRUD operation on one of your tables,
//retrieve more information about an element by clicking on it
//Select all the users that are NOT admin.
app.get("/user", (req, res) => {
  db.all("SELECT * FROM user WHERE role = 0", (err, users) => {
    if (err) {
      res.status(500).send("Internal server error");
    } else if (users.length === 0) {
      res.status(404).send("Error no users were found");
    } else {
      res.json(users);
    }
  });
});

//Store session in the database
const SQLiteStore = connectSqlite3(session);

app.use(
  session({
    store: new SQLiteStore({ db: "ag-database.db" }),
    saveUninitialized: false,
    resave: false,
    secret: "55Osa13309",
  })
);

// -------- ROUTES ------------
app.get("/", (req, res) => {
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin,
  };
  res.render("home.handlebars", model);
});
/*
app.get("/about", (req, res) => {
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin,
  };
  res.render("about.handlebars", model);
});
*/
app.get("/contact", (req, res) => {
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin,
  };
  res.render("contact.handlebars", model);
});

app.get("/education", (req, res) => {
  db.all("SELECT * FROM education", (error, theEducation) => {
    if (error) {
      console.log("Database error", error);
      res.status(500).send("Internal Server Error");
    } else {
      console.log(theEducation);
      const model = {
        education: theEducation,
        isLoggedIn: req.session.isLoggedIn,
        name: req.session.name,
        isAdmin: req.session.isAdmin,
      };
      res.render("education.handlebars", model);
    }
  });
});

app.get("/login", (req, res) => {
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin,
  };
  res.render("login.handlebars", model);
});

app.get("/projects", (req, res) => {
  db.all(
    "SELECT projectTitle, projectYear, projectID FROM projects",
    (error, theProjects) => {
      if (error) {
        res.status(500).send("Internal Server Error");
      } else {
        console.log(theProjects);
        const model = {
          projects: theProjects,
          isLoggedIn: req.session.isLoggedIn,
          name: req.session.name,
          isAdmin: req.session.isAdmin,
        };
        res.render("projects", model);
      }
    }
  );
});

//----------------------------------------Log In ----------------------------------------

async function comparePasswords(plainTextPassword, hashedPassword) {
  try {
    if (!plainTextPassword || !hashedPassword) {
      console.error(
        "Both plainTextPassword and hashedPassword must be provided"
      );
      return [false, true];
    }
    const match = await bcrypt.compare(plainTextPassword, hashedPassword);
    return [match, false];
  } catch (error) {
    return [false, true];
  }
}

bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
  if (err) {
    console.error("Error hashing the password:", err);
  } else {
    // Insert the admin user into the database
    db.run(
      "INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
      ["aleksandar", hash, 1],
      (err) => {
        if (err) {
          console.error("Error inserting admin user into the database:", err);
        } else {
          console.log("Admin user successfully inserted!");
        }
      }
    );
  }
});

app.post("/login", (req, res) => {
  const user = req.body.user;
  const plainTextPassword = req.body.pw;

  // Retrieves the hashed password from the database based on the username.
  const sql = "SELECT username, password, role FROM user WHERE username = ?";

  db.get(sql, [user], async (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }

    if (row) {
      const hashedPasswordFromDatabase = row.password;
      const [result, compareErr] = await comparePasswords(
        plainTextPassword,
        hashedPasswordFromDatabase
      );
      // Compares the hashed password with the provided plain text password.

      if (compareErr) {
        console.error(compareErr);
        return res.status(500).send("Internal Server Error");
      }

      if (result) {
        console.log(`${user} successfully logged in!  with role `, row.role);
        req.session.isAdmin = row.role == 1;
        req.session.isLoggedIn = true;
        req.session.name = user;
        res.redirect("/");
      } else {
        console.log("Login was unsuccessful, wrong user/password!");
        req.session.isAdmin = false;
        req.session.isLoggedIn = false;
        req.session.name = "";
        res.redirect("/login");
      }
    } else {
      console.log("User not found");
      req.session.isAdmin = false;
      req.session.isLoggedIn = false;
      req.session.name = "";
      res.redirect("/login");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log("Error during session destruction:", err);
    } else {
      console.log("Logged out..");
      res.redirect("/");
    }
  });
});

//----------------------------------------Session----------------------------------------
app.get("/", (req, res) => {
  console.log("Session: ", req.session);
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin,
  };
  res.render("home.handlebars", model);
});

//----------------------------------------UPDATE CRUD Project ----------------------------------------
app.put("/users/:userID", (req, res) => {
  if (req.user && req.user.role === 1) {
    const id = req.params.userID;
    const username = req.body.username;
    const password = req.body.password;
    const role = req.body.role;

    db.run(
      "UPDATE user SET username = ?, password = ?, role = ? WHERE userID = ?",
      [username, password, role, id],
      (err) => {
        if (err) {
          res.status(500).json({ error: "Server error" });
        } else {
          res.status(200).json({ message: "User updated" });
        }
      }
    );
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
});

//----------------------------------------DELETE CRUD Project----------------------------------------
//can only be preformed by an admin.
app.get("/projects/delete/:id", (req, res) => {
  const id = req.params.id;
  if (req.session.isLoggedIn === true && req.session.isAdmin === true) {
    db.run(
      "DELETE FROM projects WHERE projectID = ?",
      [id],
      function (error, theProjects) {
        if (error) {
          const model = {
            dbError: true,
            theError: error,
            idLoggedIN: req.session.isLoggedIn,
            name: req.session.name,
            isAdmin: req.session.isAdmin,
          };
          res.render("home.handlebars", model);
        } else {
          const model = {
            dbError: false,
            theError: error,
            idLoggedIN: req.session.isLoggedIn,
            name: req.session.name,
            isAdmin: req.session.isAdmin,
          };
          res.redirect("/");
        }
      }
    );
  } else {
    res.redirect("/login");
  }
});

//---------------------------------------- Read more about a specfic project (READ)  Project----------------------------------------
app.get("/projects-more/:id", (req, res) => {
  const id = req.params.id;
  db.get(
    "SELECT * FROM projects WHERE projectID=?",
    [id],
    function (error, theProjects) {
      if (error) {
      } else {
        const model = {
          project: theProjects,
          isLoggedIn: req.session.isLoggedIn,
          name: req.session.name,
          isAdmin: req.session.isAdmin,
        };
        console.log(model);
        res.render("projects-more.handlebars", model);
      }
    }
  );
});

//---------------------------------------- ADD NEW (CREATE) Project----------------------------------------
app.get("/projects/new", (req, res) => {
  if (req.session.isLoggedIn === true && req.session.isAdmin === true) {
    const model = {
      isLoggedIn: req.session.isLoggedIn,
      name: req.session.name,
      isAdmin: req.session.isAdmin,
    };

    res.render("newproject.handlebars", model);
  } else {
    res.redirect("/login");
  }
});
app.post("/projects/new", (req, res) => {
  console.log("newproject");
  const newp = [
    req.body.projectID,
    req.body.projectTitle,
    req.body.projectDescription,
    req.body.projectYear,
    req.body.userID,
  ];
  if (req.session.isLoggedIn == true && req.session.isAdmin == true) {
    db.run(
      "INSERT INTO projects (projectID,projectTitle, projectDescription, projectYear) VALUES (?,?,?,?)",
      newp,
      (error) => {
        if (error) {
          console.log("ERROR: ", error);
        } else {
          console.log("line added into the projects table!");
        }
        res.redirect("/projects/#projects");
      }
    );
  } else {
    res.redirect("/login");
  }
});

//----------------------------------------Modify project----------------------------------------
app.get("/projects/modify/:id", (req, res) => {
  console.log(req.params.id);
  if (req.session.isLoggedIn === true && req.session.isAdmin === true) {
    db.get(
      "SELECT projectTitle, projectDescription, projectYear FROM projects WHERE projectID = ?",
      [req.params.id],
      (error, project) => {
        if (error) {
          console.log("ERROR fetching project: ", error);
          res.redirect("/projects");
        } else {
          const model = {
            isLoggedIn: req.session.isLoggedIn,
            name: req.session.name,
            isAdmin: req.session.isAdmin,
            projectID: req.params.id,
            projectTitle: project.projectTitle,
            projectDescription: project.projectDescription,
            projectYear: project.projectYear,
          };
          res.render("modifyproject.handlebars", model);
        }
      }
    );
  } else {
    res.redirect("/login");
  }
});

app.post("/projects/modify/:id", (req, res) => {
  console.log("modifyproject");
  const mop = [
    req.body.projectTitle,
    req.body.projectDescription,
    req.body.projectYear,
    req.body.modifyp,
  ];
  console.log(req.body.projectTitle);
  console.log(req.body.projectDescription);
  console.log(req.body.projectYear);
  console.log(req.body.modifyp);
  if (req.session.isLoggedIn === true && req.session.isAdmin === true) {
    db.run(
      "UPDATE projects SET projectTitle = ?, projectDescription = ?, projectYear = ? WHERE projectID = ?",
      [
        req.body.projectTitle,
        req.body.projectDescription,
        req.body.projectYear,
        req.params.id,
      ],
      (error) => {
        console.log("momo");
        if (error) {
          console.log("ERROR: ", error);
        } else {
          console.log("Project updated in the projects table!");
          res.redirect("/projects");
        }
      }
    );
  } else {
    res.redirect("/login");
  }
});

app.get("/projects1111", (req, res) => {
  // Check if projectsData already exists in the database
  db.get("SELECT COUNT(*) AS count FROM projectsData", (error, row) => {
    if (error) {
      console.error("Error checking if data exists:", error);
      res.status(500).send("Internal Server Error");
      return;
    }

    if (row.count === 0) {
      // Projects data doesn't exist, insert it into the database
      const projectsData = [
        // ... your projects data here ...
      ];

      // Insert projects into the database
      const insertPromises = projectsData.map((project) => {
        return new Promise((resolve, reject) => {
          db.run(
            `INSERT INTO projectsData (title, description) VALUES (?, ?)`,
            [project.title, project.description],
            (error) => {
              if (error) {
                console.error("Error inserting project:", error);
                reject(error);
              } else {
                console.log("---> Project inserted successfully!");
                resolve();
              }
            }
          );
        });
      });

      // Wait for all insert operations to complete
      Promise.all(insertPromises)
        .then(() => {
          // Redirect to the same route to fetch and render the data
          res.redirect("/projects");
        })
        .catch((error) => {
          // Handle error if any of the insert operations fail
          console.error("Error inserting projects:", error);
          res.status(500).send("Internal Server Error");
        });
    } else {
      // Projects data already exists, retrieve and render it
      db.all("SELECT * FROM projectsData", (error, projectsData) => {
        if (error) {
          console.error("Error retrieving projects data:", error);
          res.status(500).send("Internal Server Error");
        } else {
          // Parse the JSON data from the database response
          projectsData = projectsData.map((project) => {
            return {
              title: project.title,
              description: project.description,
            };
          });
          const model = {
            projectsData: projectsData,
            isLoggedIn: req.session.isLoggedIn,
            name: req.session.name,
            isAdmin: req.session.isAdmin,
          };
          res.render("projects.handlebars", model);
        }
      });
    }
  });
});

// run the server and make it listen to the port
app.listen(port, () => {
  console.log(`Server running and listening on port ${port}...`);
});
