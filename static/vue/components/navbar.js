const Navbar = Vue.component("Navbar", {
    template: `
  
    <nav class="navbar navbar-expand-lg sticky-top border-bottom navbar-container">
    <div class="container">
      <a class="navbar-brand" href="/">
        <span class="navbar-head">LIQUID DEMOCRACY</span>
      </a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNavAltMarkup">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item active mr-3">
            <a class="nav-link" href="/#/" style="display: flex; flex-direction: column; align-items: center; text-align: center;">
              <i class="fas fa-home fa-lg text-center" style="color: black"></i>
              <router-link class="menutext mt-2" to="/">Home</router-link>
            </a>
          </li>
          <li class="nav-item mr-3">
            <a class="nav-link" href="/#/about" style="display: flex; flex-direction: column; align-items: center; text-align: center;">
              <i class="fas fa-info-circle fa-lg text-center" style="color: black"></i>
              <div class="menutext mt-2"><router-link class="menutext mt-2" to="/about">About Us</router-link></div>
            </a>
          </li>
          <li class="nav-item logout-thor mr-3">
            <a @click='logout' class="nav-link active d-lg-block" style="display: flex; flex-direction: column; align-items: center; text-align: center; border: none; background: none;">
                <i class="fas fa-sign-out-alt fa-lg text-center" style="color: black"></i>
              <div class="menutext">Logout</div>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
  
  
    
    
    `,
    data() {
      return {
        role: localStorage.getItem("role"),
        is_login: localStorage.getItem("auth-token"),
        id: localStorage.getItem("id"),
        inactivityTimeout: 5 * 60 * 1000, // 30 minutes in milliseconds
        inactivityTimer: null,
      };
    },
    methods: {
      logout() {
        localStorage.removeItem("auth-token");
        localStorage.removeItem("role");
        localStorage.removeItem("id");
        localStorage.removeItem("username");
        this.$router.push({ path: "/login" });
      },
      handleUserActivity() {
        // Update the last activity timestamp
        localStorage.setItem("lastActivityTimestamp", Date.now().toString());
      },
      checkInactivity() {
        const lastActivityTimestamp = localStorage.getItem(
          "lastActivityTimestamp"
        );
        const currentTime = Date.now();
  
        if (
          lastActivityTimestamp &&
          currentTime - lastActivityTimestamp > this.inactivityTimeout
        ) {
          // User has been inactive for too long, clear local storage
          this.clearLocalStorage();
        }
      },
      clearLocalStorage() {
        localStorage.removeItem("auth-token");
        localStorage.removeItem("role");
        this.$router.push({ path: "/login" });
      },
      startInactivityTimer() {
        this.inactivityTimer = setInterval(() => {
          this.checkInactivity();
        }, 60000); // Check every minute (adjust as needed)
      },
      stopInactivityTimer() {
        clearInterval(this.inactivityTimer);
      },
    },
    mounted() {
      // Set up event listeners to track user activity
      document.addEventListener("mousemove", this.handleUserActivity);
      document.addEventListener("keydown", this.handleUserActivity);
      document.title = "Navbar";
  
      // Start the inactivity timer
      this.startInactivityTimer();
    },
    beforeDestroy() {
      // Clean up event listeners and the inactivity timer
      document.removeEventListener("mousemove", this.handleUserActivity);
      document.removeEventListener("keydown", this.handleUserActivity);
      this.stopInactivityTimer();
    },
  });
  
  export default Navbar;
  