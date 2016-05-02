var viewModel = {
        navigationItems: new ko.observableArray([
            {label: "Home", url: "/", subitems: null},
            {label: "Meet Darilyn", url: "/aboutus", subitems: null},
            {label: "Services", url: "/services", subitems: null},
            {label: "Events", url: null, subitems: [
              {label: "About Events", url: "/events"},
              {label: "Upcoming events", url: "/events/upcoming"}
            ]},          
            {label: "Contact", url: "/contact", subitems: null},
            {label: "Testimonial", url: "/testimonial", subitems: null},
            {label: "Blog", url: "/blog", subitems: null}
        ])() // Initially blank
    };
ko.applyBindings(viewModel);
