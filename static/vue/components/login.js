const Login = Vue.component("login", {
  template: `
  <div class="main-container d-flex flex-column justify-content-center">
  <div class="container">
    <div class="row justify-content-center">
      <div class="form-container col-md-6 p-5">
        <h2 class="text-center">Login</h2>
        <div class="alert alert-danger" v-if="error">
          {{ error }}
        </div>
          <div class="form-group p-1">
            <label for="email">Email:</label>
            <input class="input-field" type="text" class="form-control login-input" id="username" name="username" placeholder="Enter email"
            v-model="cred.email">
          </div>
          <div class="form-group p-1">
            <label for="password">Password:</label>
            <input type="password" class="form-control mb-2" id="password" name="password" placeholder="Enter password"
            v-model="cred.password">
          </div>
          <div class="d-flex flex-row">
          <button class="button-86" type="submit" role="button" @click='login'>Login</button>
          </div>
          <p class="mt-3">Don't have an account? <router-link to="/register">Register as Voter here</router-link></p>
      </div>
    </div>
  </div>
  </div>`,
  data() {
    return {
      cred: {
        email: null,
        password: null,
      },
      error: null,
    };
  },
  methods: {
    async login() {
      const res = await fetch("/user-login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(this.cred),
      });
      if (res.ok) {
        const data = await res.json();
        console.log(data);
        localStorage.setItem("auth-token", data.token);
        localStorage.setItem("role", data.role);
        localStorage.setItem("id", data.id);
        localStorage.setItem("username", data.username);
        this.$router.push("/");
      } else {
        const data = await res.json();
        console.log(data);
        this.error = data.message;
      }
    },
  },
  mounted: function () {
    document.title = "Login";
  },
});

export default Login;
