function create_navbar() {
    let navlinks = [
        ['Home','/home'],
        ['Login','/login'],
        ['Tags','/tags'],
        ['Projects','/projects'],
        ['Specializations','/specializations'],
        ['Procedures','/procedures'],
        ['Profile','/profile'],
        ['Form','/form']
    ];
    let ul = document.createElement('ul');
    ul.id = "nav1";
    navlinks.forEach(function(item) {
        let link = document.createElement('a');
        link.innerHTML = item[0]+"</br>";
        link.href = item[1];
        link.id = "nav";
        ul.appendChild(link);
    })
    document.body.append(ul);
}