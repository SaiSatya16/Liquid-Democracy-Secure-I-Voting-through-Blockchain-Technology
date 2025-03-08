const Voterhome = Vue.component("voterhome", {
  template: `
    <div class="main-container pb-5">
      <div class="container">
        <div class="row">
          <div class="col-lg-8 offset-lg-2">
            <div class="jumbotron pt-3 pb-3">
              <h1 class="display-4 greeting">Welcome, {{ username }}!</h1>
            </div>
            <div class="alert alert-danger" v-if="error">
              {{ error }}
            </div>
            <div class="mt-2">
              <div v-if="loading" class="loader"></div>
              <div v-else-if="schemes.length == 0">
                <p class="text-center">No schemes available</p>
              </div>
              <div v-else>
                <h2>Available Schemes</h2>
                <ul class="list-group">
                  <li class="list-group-item" v-for="scheme in schemes" :key="scheme.id">
                    <h5>{{ scheme.name }}</h5>
                    <p class="text-muted">{{ scheme.description }}</p>
                    <p>Your voting weight: {{ scheme.userWeight }}</p>
                    <p>Delegation chain length: {{ scheme.delegationChainLength }}</p>
                    <p>Voting power distribution (Gini coefficient): {{ scheme.giniCoefficient.toFixed(4) }}</p>
                    
                    <div v-if="!scheme.delegated_to">
                      <div v-if="scheme.allowed_to_vote">
                        <div class="btn-group" role="group">
                          <div class="form-check form-check-inline">
                            <input
                              class="form-check form-check-inline"
                              type="radio"
                              :name="'agree' + scheme.id"
                              :id="'agree' + scheme.id"
                              value="true"
                              v-model="scheme.Vote"
                            />
                            <label
                              class="form-check form-check-inline"
                              :for="'agree' + scheme.id"
                            >Agree</label>

                            <input
                              class="form-check form-check-inline"
                              type="radio"
                              :name="'disagree' + scheme.id"
                              :id="'disagree' + scheme.id"
                              value="false"
                              v-model="scheme.Vote"
                            />
                            <label
                              class="form-check form-check-inline"
                              :for="'disagree' + scheme.id"
                            >Disagree</label>

                            <button
                              type="button"
                              class="btn btn-sm btn-outline-primary"
                              @click="vote(scheme)"
                            >
                              Vote
                            </button>
                          </div>
                        </div>
                      </div>
                      <div v-else>
                        <div class="progress">
                          <div
                            class="progress-bar bg-success"
                            role="progressbar"
                            :style="'width:' + scheme.trueVotePercentage + '%'"
                          >
                            <span>{{ scheme.trueVotePercentage.toFixed(2) }}%</span>
                          </div>
                          <div
                            class="progress-bar bg-danger"
                            role="progressbar"
                            :style="'width:' + scheme.falseVotePercentage + '%'"
                          >
                            <span>{{ scheme.falseVotePercentage.toFixed(2) }}%</span>
                          </div>
                        </div>
                      </div>
                      <div class="mt-2" v-if="scheme.allowed_to_vote">
                        <select v-model="scheme.delegateeId" class="form-control">
                          <option value="">Select a voter to delegate</option>
                          <option v-for="voter in scheme.not_delegated_users" :key="voter.id" :value="voter.id">
                            {{ voter.username }}
                          </option>
                        </select>
                        <button @click="showDelegationWarning(scheme)" class="btn btn-primary mt-2">
                          Delegate Vote
                        </button>
                      </div>
                    </div>
                    <div v-else>
                      <div class="progress">
                        <div
                          class="progress-bar bg-success"
                          role="progressbar"
                          :style="'width:' + scheme.trueVotePercentage + '%'"
                        >
                          <span>{{ scheme.trueVotePercentage.toFixed(2) }}%</span>
                        </div>
                        <div
                          class="progress-bar bg-danger"
                          role="progressbar"
                          :style="'width:' + scheme.falseVotePercentage + '%'"
                        >
                          <span>{{ scheme.falseVotePercentage.toFixed(2) }}%</span>
                        </div>
                      </div>
                      <p>You have delegated your vote for this scheme to {{ scheme.delegated_to.username }}</p>
                    </div>
                    
                    <button @click="getDelegationChain(scheme.id)" class="btn btn-info mt-2">View Delegation Chain</button>
                    <button @click="getVotingPowerDistribution(scheme.id)" class="btn btn-secondary mt-2">View Voting Power Distribution</button>
                    
                    <canvas :id="'votingPowerChart' + scheme.id" class="mt-3"></canvas>
                  </li>
                </ul>
              </div>
            </div>
            
            <!-- System security information -->
            <div class="mt-4">
              <h4>System Security Information</h4>
              <p>Security Strength: {{ securityStrength }} bits</p>
              <p>Probability of Successful Attack: {{ attackProbability.toExponential(2) }}</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Delegation Warning Modal -->
      <transition name="modal">
        <div class="modal-mask" v-if="showWarning">
          <div class="modal-wrapper">
            <div class="modal-container">
              <div class="modal-header">
                <h3>Warning</h3>
              </div>
              <div class="modal-body">
                <p>Warning: Once you delegate your vote, it cannot be undone. Are you sure you want to proceed?</p>
              </div>
              <div class="modal-footer">
                <button class="btn btn-secondary" @click="closeWarning">
                  Cancel
                </button>
                <button class="btn btn-primary" @click="confirmDelegation">
                  Confirm Delegation
                </button>
              </div>
            </div>
          </div>
        </div>
      </transition>
    </div>
  `,
  data() {
    return {
      userRole: localStorage.getItem("role"),
      token: localStorage.getItem("auth-token"),
      username: localStorage.getItem("username"),
      user_id: localStorage.getItem("id"),
      error: null,
      schemes: [],
      showWarning: false,
      currentScheme: null,
      securityStrength: 256, // Assuming AES-128
      attackProbability: Math.pow(2, -256),
      loading: false,
    };
  },
  methods: {
    async getSchemes() {
      this.loading = true;
      try {
        const res = await fetch("/scheme/" + this.user_id, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            "Authentication-Token": this.token,
            "Authentication-Role": this.userRole,
          },
        });
        if (res.ok) {
          const data = await res.json();
          this.schemes = data.map(scheme => ({
            ...scheme,
            trueVotePercentage: (scheme.true_vote_count / (scheme.true_vote_count + scheme.false_vote_count)) * 100,
            falseVotePercentage: (scheme.false_vote_count / (scheme.true_vote_count + scheme.false_vote_count)) * 100,
          }));
        } else {
          const data = await res.json();
          this.error = data.error_message;
        }
      } catch (error) {
        this.error = "An error occurred while fetching schemes.";
      } finally {
        this.loading = false;
      }
    },

    async vote(scheme) {
      this.loading = true;
      try {
        const res = await fetch("/vote", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authentication-Token": this.token,
            "Authentication-Role": this.userRole,
          },
          body: JSON.stringify({
            scheme_id: scheme.id,
            user_id: this.user_id,
            vote: scheme.Vote,
          }),
        });
        if (res.ok) {
          await this.getSchemes();
        } else {
          const data = await res.json();
          this.error = data.error_message;
        }
      } catch (error) {
        this.error = "An error occurred while voting.";
      } finally {
        this.loading = false;
      }
    },

    showDelegationWarning(scheme) {
      if (!scheme.delegateeId) {
        this.error = "Please select a voter to delegate";
        return;
      }
      this.currentScheme = scheme;
      this.showWarning = true;
    },

    closeWarning() {
      this.showWarning = false;
      this.currentScheme = null;
    },

    async confirmDelegation() {
      if (!this.currentScheme) return;
      this.loading = true;
      try {
        const res = await fetch("/delegation", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authentication-Token": this.token,
            "Authentication-Role": this.userRole,
          },
          body: JSON.stringify({
            delegator_id: this.user_id,
            delegatee_id: this.currentScheme.delegateeId,
            scheme_id: this.currentScheme.id,
          }),
        });
        if (res.ok) {
          await this.getSchemes();
          this.closeWarning();
        } else {
          const data = await res.json();
          this.error = data.error_message;
        }
      } catch (error) {
        this.error = "An error occurred while delegating.";
      } finally {
        this.loading = false;
      }
    },

    async getDelegationChain(schemeId) {
      this.loading = true;
      try {
        const res = await fetch(`/delegation-chain/${this.user_id}/${schemeId}`, {
          headers: {
            "Authentication-Token": this.token,
          },
        });
        if (res.ok) {
          const chain = await res.json();
          alert(`Your delegation chain: ${chain.join(' -> ')}`);
        } else {
          const data = await res.json();
          this.error = data.error_message;
        }
      } catch (error) {
        this.error = "An error occurred while fetching the delegation chain.";
      } finally {
        this.loading = false;
      }
    },

    async getVotingPowerDistribution(schemeId) {
      this.loading = true;
      try {
        const res = await fetch(`/voting-power-distribution/${schemeId}`, {
          headers: {
            "Authentication-Token": this.token,
          },
        });
        if (res.ok) {
          const distribution = await res.json();
          this.showDistributionChart(distribution, schemeId);
        } else {
          const data = await res.json();
          this.error = data.error_message;
        }
      } catch (error) {
        this.error = "An error occurred while fetching voting power distribution.";
      } finally {
        this.loading = false;
      }
    },

    showDistributionChart(distribution, schemeId) {
      const ctx = document.getElementById('votingPowerChart' + schemeId).getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: distribution.labels,
          datasets: [{
            label: 'Voting Power',
            data: distribution.data,
            backgroundColor: 'rgba(75, 192, 192, 0.6)',
          }]
        },
        options: {
          responsive: true,
          scales: {
            y: {
              beginAtZero: true
            }
          }
        }
      });
    },
  },
  mounted() {
    this.getSchemes();
    document.title = "Voter Home";
  },
});

export default Voterhome;