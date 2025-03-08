const Adminhome = Vue.component("adminhome", {
    template: `
    <div class="main-container pb-5">
        <div class="container">
            <div class="row">
                <div class="col-lg-8 offset-lg-2">
                    <!-- Welcome Message -->
                    <div class="jumbotron pt-3 pb-3">
                        <h1 class="display-4 greeting">Welcome, {{username}}!</h1>
                        <p class="scope">You can Create, Edit, Delete Schemes</p>
                        <button class="add-course-btn" data-bs-toggle="modal" data-bs-target="#addSchemeModal">Add Scheme
                            <i class="fa fa-plus" aria-hidden="true"></i>
                        </button>
                    </div>
                    <div class="alert alert-danger" v-if="error">
                        {{ error }}
                    </div>
                    <div class="mt-4">
                        <div v-if="loading" class="loader"></div>
                        <div v-else-if="schemes.length == 0">
                            <p class="text-center">No schemes available</p>
                        </div>
                        <div v-else>
                            <h2>Schemes</h2>
                            <ul class="list-group">
                                <li class="list-group-item" v-for="scheme in schemes" :key="scheme.id">
                                    <h5>{{ scheme.name }}</h5>
                                    <p muted>{{ scheme.description }}</p>
                                    <div class="btn-group" role="group">
                                        <button type="button" class="btn btn-sm btn-outline-secondary" :data-bs-target="'#editSchemeModal' + scheme.id" data-bs-toggle="modal">Edit</button>
                                        <button type="button" class="btn btn-sm btn-outline-danger" @click="deleteScheme(scheme.id)">Delete</button>
                                    </div>
                                    <div class="progress mt-3">
                                        <div class="progress-bar bg-success" role="progressbar" :style="'width:' + scheme.true_vote_percentage + '%'">
                                            <span>{{ scheme.true_vote_percentage }}%</span>
                                        </div>
                                        <div class="progress-bar bg-danger" role="progressbar" :style="'width:' + scheme.false_vote_percentage + '%'">
                                            <span>{{ scheme.false_vote_percentage }}%</span>
                                        </div>
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div> 
            </div> 
        </div> 

        <div class="modal fade" id="addSchemeModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="addSchemeModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="addSchemeModalLabel">Add Course</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="my-3">
                            <label for="roomname">Enter Scheme Name</label>
                            <input v-model="scheme_name" type="text" id="scheme_name" class="form-control" placeholder="Scheme Name">
                        </div>
                        <div class="my-3">
                            <label for="scheme_description">Enter Scheme Description</label>
                            <textarea v-model="scheme_description" class="form-control"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" @click="addScheme" class="btn btn-primary" data-bs-dismiss="modal">Submit</button>
                    </div>
                </div>
            </div>
        </div>

        <div v-for="scheme in schemes" :key="scheme.id" class="modal fade" :id="'editSchemeModal' + scheme.id" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="editSchemeModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="editSchemeModalLabel">Edit Scheme</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="my-3">
                            <label for="roomname">Enter Scheme Name</label>
                            <input v-model="scheme.name" type="text" id="scheme_name" class="form-control" placeholder="Scheme Name">
                        </div>
                        <div class="my-3">
                            <label for="scheme_description">Enter Scheme Description</label>
                            <textarea v-model="scheme.description" class="form-control"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" @click="editScheme(scheme)" class="btn btn-primary" data-bs-dismiss="modal">Submit</button>
                    </div>
                </div>
            </div>
        </div>
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
            scheme_name: null,
            scheme_description: null,
            loading: false,
        }
    },

    methods: {
        async getschemes() {
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
                    console.log(data);
                    this.schemes = data;
                } else {
                    const data = await res.json();
                    console.log(data);
                    this.error = data.error_message;
                }
            } catch (error) {
                this.error = "An error occurred while fetching schemes.";
            } finally {
                this.loading = false;
            }
        },

        async addScheme() {
            this.loading = true;
            try {
                const res = await fetch("/scheme", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authentication-Token": this.token,
                        "Authentication-Role": this.userRole,
                    },
                    body: JSON.stringify({
                        name: this.scheme_name,
                        description: this.scheme_description,
                    }),
                });
                if (res.ok) {
                    await this.getschemes();
                    this.scheme_name = null;
                    this.scheme_description = null;
                } else {
                    const data = await res.json();
                    console.log(data);
                    this.error = data.error_message;
                }
            } catch (error) {
                this.error = "An error occurred while adding the scheme.";
            } finally {
                this.loading = false;
            }
        },

        async deleteScheme(id) {
            this.loading = true;
            try {
                const res = await fetch("/scheme/" + id, {
                    method: "DELETE",
                    headers: {
                        "Content-Type": "application/json",
                        "Authentication-Token": this.token,
                        "Authentication-Role": this.userRole,
                    },
                });
                if (res.ok) {
                    await this.getschemes();
                } else {
                    const data = await res.json();
                    console.log(data);
                    this.error = data.error_message;
                }
            } catch (error) {
                this.error = "An error occurred while deleting the scheme.";
            } finally {
                this.loading = false;
            }
        },

        async editScheme(scheme) {
            this.loading = true;
            try {
                const res = await fetch("/scheme/" + scheme.id, {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        "Authentication-Token": this.token,
                        "Authentication-Role": this.userRole,
                    },
                    body: JSON.stringify({
                        name: scheme.name,
                        description: scheme.description,
                    }),
                });
                if (res.ok) {
                    await this.getschemes();
                } else {
                    const data = await res.json();
                    console.log(data);
                    this.error = data.error_message;
                }
            } catch (error) {
                this.error = "An error occurred while editing the scheme.";
            } finally {
                this.loading = false;
            }
        }
    },

    mounted: function() {
        this.getschemes();
        document.title = "Admin Home";
    },
});

export default Adminhome;